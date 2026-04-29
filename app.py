import csv
import io
import json
import os
import logging
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import re

from flask import (
    Flask, redirect, url_for, session, request,
    render_template, flash, jsonify, g, Response
)
from urllib.parse import urlparse
from sqlalchemy import func

logger = logging.getLogger(__name__)

from models.models import (
    db, User, DataSource, Dashboard, Widget, Report,
    Region, Product, Customer, Sale, Employee, RevenueTarget
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s: %(message)s',
)

app = Flask(__name__)
_secret = os.environ.get('SECRET_KEY', 'dev-secret-change-in-production')
if _secret == 'dev-secret-change-in-production':
    if os.environ.get('FLASK_ENV') == 'production':
        raise RuntimeError(
            'Refusing to start: SECRET_KEY must be set to a strong random value in production. '
            'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
        )
    logger.warning('Using default SECRET_KEY. Set the SECRET_KEY environment variable in production.')
app.config['SECRET_KEY'] = _secret
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 'sqlite:///insightforge.db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Enable Secure flag in production (HTTPS); keep off for local HTTP dev
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
# Limit request body to 2 MB to prevent DoS via oversized POST payloads
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

db.init_app(app)

PER_PAGE = 20           # records per page for list views
MAX_PAGE = 10000        # upper bound to prevent DoS via absurdly large page numbers
MAX_FAILED_LOGINS = 5   # failed attempts before lockout
LOCKOUT_MINUTES = 15    # lockout duration

limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri='memory://',
    default_limits=[],  # no global limit; apply per-route only
)


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'"
    )
    response.headers['Permissions-Policy'] = (
        'camera=(), microphone=(), geolocation=(), payment=()'
    )
    # HSTS: only sent over HTTPS to avoid breaking plain-HTTP dev environments.
    if app.config.get('SESSION_COOKIE_SECURE'):
        response.headers['Strict-Transport-Security'] = (
            'max-age=31536000; includeSubDomains'
        )
    return response


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(429)
def rate_limited(e):
    return render_template(
        'error.html', code=429,
        message='Too many requests. Please wait a moment and try again.'
    ), 429


@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403, message='Access denied.'), 403


@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, message='Page not found.'), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return render_template('error.html', code=405, message='Method not allowed.'), 405


@app.errorhandler(413)
def request_too_large(e):
    return render_template('error.html', code=413, message='Request too large. Maximum upload size is 2 MB.'), 413


@app.errorhandler(500)
def server_error(e):
    logger.exception('Unhandled server error: %s', e)
    return render_template('error.html', code=500, message='Internal server error.'), 500


# ---------------------------------------------------------------------------
# CSRF protection
# ---------------------------------------------------------------------------

def get_csrf_token():
    """Return (and lazily create) a per-session CSRF token."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']


@app.before_request
def csrf_protect():
    """Reject state-changing requests that lack a valid CSRF token."""
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        token = session.get('_csrf_token', '')
        form_token = request.form.get('_csrf_token', '')
        if not token or not secrets.compare_digest(token, form_token):
            logger.warning('CSRF validation failed: %s %s from %s',
                           request.method, request.path, request.remote_addr)
            return render_template(
                'error.html', code=403,
                message='Invalid or missing security token. Please go back and try again.'
            ), 403


# Make csrf_token() callable from every template without an explicit import.
app.jinja_env.globals['csrf_token'] = get_csrf_token


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.path))
        # Guard against stale session (user deleted after login).
        # Cache in g so current_user() avoids a second DB round-trip.
        if not hasattr(g, 'current_user'):
            user = db.session.get(User, session['user_id'])
            if user is None:
                session.clear()
                flash('Your session has expired. Please log in again.', 'warning')
                return redirect(url_for('login'))
            g.current_user = user
        return f(*args, **kwargs)
    return decorated


def current_user():
    """Return the logged-in User, using the g-cache set by login_required."""
    if hasattr(g, 'current_user'):
        return g.current_user
    if 'user_id' in session:
        return db.session.get(User, session['user_id'])
    return None


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

def _safe_next(next_url):
    """Return next_url only if it is a relative path on this host."""
    if next_url:
        parsed = urlparse(next_url)
        # Allow only relative URLs (no scheme/netloc) to prevent open redirect.
        if not parsed.scheme and not parsed.netloc and next_url.startswith('/'):
            return next_url
    return None


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit('20 per minute; 100 per hour', methods=['POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    next_url = _safe_next(request.args.get('next') or request.form.get('next'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash('Username and password are required.', 'danger')
            return render_template('login.html', next=next_url)
        user = db.session.execute(
            db.select(User).filter_by(username=username)
        ).scalar_one_or_none()
        if user:
            # Check active lockout
            if user.locked_until:
                now_utc = datetime.now(timezone.utc)
                locked_ts = user.locked_until
                if locked_ts.tzinfo is None:
                    locked_ts = locked_ts.replace(tzinfo=timezone.utc)
                if locked_ts > now_utc:
                    remaining = max(1, int((locked_ts - now_utc).total_seconds() / 60) + 1)
                    logger.warning('Login attempt on locked account: user=%s ip=%s', username, request.remote_addr)
                    flash(f'Account locked. Try again in {remaining} minute(s).', 'danger')
                    return render_template('login.html', next=next_url)
                # Lockout expired — clear it before checking password
                user.locked_until = None
                user.failed_logins = 0

            if user.check_password(password):
                user.failed_logins = 0
                user.locked_until = None
                db.session.commit()
                session.clear()  # drop old session data (session fixation mitigation)
                session['user_id'] = user.id
                session['username'] = user.username
                logger.info('Successful login: user=%s ip=%s', username, request.remote_addr)
                flash(f'Welcome back, {user.username}!', 'success')
                return redirect(next_url or url_for('index'))

            # Wrong password — increment failure counter
            user.failed_logins = (user.failed_logins or 0) + 1
            if user.failed_logins >= MAX_FAILED_LOGINS:
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
                db.session.commit()
                logger.warning('Account locked: user=%s ip=%s attempts=%d',
                               username, request.remote_addr, user.failed_logins)
                flash(f'Too many failed attempts. Account locked for {LOCKOUT_MINUTES} minutes.', 'danger')
                return render_template('login.html', next=next_url)
            db.session.commit()

        logger.warning('Failed login attempt: user=%s ip=%s', username, request.remote_addr)
        flash('Invalid username or password.', 'danger')
    return render_template('login.html', next=next_url)


_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
_USERNAME_RE = re.compile(r'^[a-zA-Z0-9_-]+$')


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit('10 per minute; 30 per hour', methods=['POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        error = None
        if not username or len(username) < 3:
            error = 'Username must be at least 3 characters.'
        elif len(username) > 80:
            error = 'Username must be 80 characters or fewer.'
        elif not _USERNAME_RE.match(username):
            error = 'Username may only contain letters, numbers, hyphens, and underscores.'
        elif not password or len(password) < 8:
            error = 'Password must be at least 8 characters.'
        elif not any(c.isdigit() for c in password):
            error = 'Password must contain at least one number.'
        elif password != confirm:
            error = 'Passwords do not match.'
        elif email and not _EMAIL_RE.match(email):
            error = 'Please enter a valid email address.'
        elif db.session.execute(
            db.select(User).filter_by(username=username)
        ).scalar_one_or_none():
            error = 'Username already taken.'
        elif email and db.session.execute(
            db.select(User).filter_by(email=email)
        ).scalar_one_or_none():
            error = 'Email already registered.'
        if error:
            flash(error, 'danger')
            return render_template('register.html')
        user = User(username=username, email=email or None)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        session['user_id'] = user.id
        session['username'] = user.username
        flash('Account created! Welcome to InsightForge.', 'success')
        return redirect(url_for('index'))
    return render_template('register.html')


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# ---------------------------------------------------------------------------
# Main dashboard
# ---------------------------------------------------------------------------

@app.route('/')
@login_required
def index():
    user = current_user()
    total_sales = db.session.scalar(db.select(func.count()).select_from(Sale))
    total_revenue = db.session.scalar(db.select(func.sum(Sale.total_amount))) or 0
    total_customers = db.session.scalar(db.select(func.count()).select_from(Customer))
    total_products = db.session.scalar(db.select(func.count()).select_from(Product))

    # Recent sales (last 30 days)
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    recent_sales = db.session.scalar(
        db.select(func.count()).select_from(Sale).where(Sale.sale_date >= thirty_days_ago)
    )

    # Top 5 products by revenue
    top_products = db.session.execute(
        db.select(Product.name, func.sum(Sale.total_amount).label('revenue'))
        .join(Sale, Sale.product_id == Product.id)
        .group_by(Product.id)
        .order_by(func.sum(Sale.total_amount).desc())
        .limit(5)
    ).all()

    dashboards = db.session.scalars(
        db.select(Dashboard).filter_by(user_id=user.id)
        .order_by(Dashboard.created_at.desc()).limit(5)
    ).all()
    reports = db.session.scalars(
        db.select(Report).filter_by(user_id=user.id)
        .order_by(Report.created_at.desc()).limit(5)
    ).all()

    return render_template(
        'index.html',
        user=user,
        total_sales=total_sales,
        total_revenue=total_revenue,
        total_customers=total_customers,
        total_products=total_products,
        recent_sales=recent_sales,
        top_products=top_products,
        dashboards=dashboards,
        reports=reports,
        now=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Dashboards
# ---------------------------------------------------------------------------

@app.route('/dashboards')
@login_required
def dashboards():
    user = current_user()
    page = min(max(1, request.args.get('page', 1, type=int)), MAX_PAGE)
    total = db.session.scalar(
        db.select(func.count()).select_from(Dashboard).where(Dashboard.user_id == user.id)
    )
    total_pages = max(1, -(-total // PER_PAGE))  # ceiling division
    page = min(page, total_pages)
    all_dashboards = db.session.scalars(
        db.select(Dashboard).filter_by(user_id=user.id)
        .order_by(Dashboard.created_at.desc())
        .limit(PER_PAGE).offset((page - 1) * PER_PAGE)
    ).all()
    return render_template(
        'dashboards.html', user=user, dashboards=all_dashboards,
        page=page, total_pages=total_pages,
    )


@app.route('/dashboards/new', methods=['GET', 'POST'])
@login_required
def new_dashboard():
    user = current_user()
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        if not name:
            flash('Dashboard name is required.', 'danger')
            return render_template('dashboard_form.html', user=user)
        if len(name) > 120:
            flash('Name must be 120 characters or fewer.', 'danger')
            return render_template('dashboard_form.html', user=user)
        if len(description) > 1000:
            flash('Description must be 1000 characters or fewer.', 'danger')
            return render_template('dashboard_form.html', user=user)
        dashboard = Dashboard(name=name, description=description, user_id=user.id)
        db.session.add(dashboard)
        db.session.commit()
        flash(f'Dashboard "{name}" created.', 'success')
        return redirect(url_for('view_dashboard', dashboard_id=dashboard.id))
    return render_template('dashboard_form.html', user=user)


@app.route('/dashboards/<int:dashboard_id>')
@login_required
def view_dashboard(dashboard_id):
    user = current_user()
    dashboard = db.first_or_404(
        db.select(Dashboard).filter_by(id=dashboard_id, user_id=user.id)
    )
    widgets = db.session.scalars(
        db.select(Widget).filter_by(dashboard_id=dashboard_id).order_by(Widget.position)
    ).all()
    widget_configs = {}
    for w in widgets:
        try:
            widget_configs[w.id] = json.loads(w.config) if w.config else {}
        except (ValueError, TypeError):
            widget_configs[w.id] = {}
    return render_template(
        'dashboard_view.html',
        user=user,
        dashboard=dashboard,
        widgets=widgets,
        widget_configs=widget_configs,
    )


@app.route('/dashboards/<int:dashboard_id>/delete', methods=['POST'])
@login_required
def delete_dashboard(dashboard_id):
    user = current_user()
    dashboard = db.first_or_404(
        db.select(Dashboard).filter_by(id=dashboard_id, user_id=user.id)
    )
    db.session.delete(dashboard)
    db.session.commit()
    flash(f'Dashboard "{dashboard.name}" deleted.', 'info')
    return redirect(url_for('dashboards'))


# ---------------------------------------------------------------------------
# Data Sources
# ---------------------------------------------------------------------------

@app.route('/data-sources')
@login_required
def data_sources():
    user = current_user()
    page = min(max(1, request.args.get('page', 1, type=int)), MAX_PAGE)
    total = db.session.scalar(
        db.select(func.count()).select_from(DataSource).where(DataSource.user_id == user.id)
    )
    total_pages = max(1, -(-total // PER_PAGE))
    page = min(page, total_pages)
    sources = db.session.scalars(
        db.select(DataSource).filter_by(user_id=user.id)
        .order_by(DataSource.created_at.desc())
        .limit(PER_PAGE).offset((page - 1) * PER_PAGE)
    ).all()
    return render_template(
        'data_sources.html', user=user, sources=sources,
        page=page, total_pages=total_pages,
    )


@app.route('/data-sources/new', methods=['GET', 'POST'])
@login_required
def new_data_source():
    user = current_user()
    ALLOWED_TYPES = {'csv', 'database', 'api', 'excel'}
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        data_type = request.form.get('data_type', '').strip()
        connection_string = request.form.get('connection_string', '').strip()
        if not name or not data_type:
            flash('Name and type are required.', 'danger')
            return render_template('data_source_form.html', user=user)
        if len(name) > 120:
            flash('Name must be 120 characters or fewer.', 'danger')
            return render_template('data_source_form.html', user=user)
        if data_type not in ALLOWED_TYPES:
            flash('Invalid data source type.', 'danger')
            return render_template('data_source_form.html', user=user)
        source = DataSource(
            name=name,
            data_type=data_type,
            connection_string=connection_string or None,
            user_id=user.id,
        )
        db.session.add(source)
        db.session.commit()
        flash(f'Data source "{name}" added.', 'success')
        return redirect(url_for('data_sources'))
    return render_template('data_source_form.html', user=user)


@app.route('/data-sources/<int:source_id>/delete', methods=['POST'])
@login_required
def delete_data_source(source_id):
    user = current_user()
    source = db.first_or_404(
        db.select(DataSource).filter_by(id=source_id, user_id=user.id)
    )
    db.session.delete(source)
    db.session.commit()
    flash(f'Data source "{source.name}" deleted.', 'info')
    return redirect(url_for('data_sources'))


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

@app.route('/reports')
@login_required
def reports():
    user = current_user()
    page = min(max(1, request.args.get('page', 1, type=int)), MAX_PAGE)
    total = db.session.scalar(
        db.select(func.count()).select_from(Report).where(Report.user_id == user.id)
    )
    total_pages = max(1, -(-total // PER_PAGE))
    page = min(page, total_pages)
    all_reports = db.session.scalars(
        db.select(Report).filter_by(user_id=user.id)
        .order_by(Report.created_at.desc())
        .limit(PER_PAGE).offset((page - 1) * PER_PAGE)
    ).all()
    return render_template(
        'reports.html', user=user, reports=all_reports,
        page=page, total_pages=total_pages,
    )


@app.route('/reports/new', methods=['GET', 'POST'])
@login_required
def new_report():
    user = current_user()
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        if not name:
            flash('Report name is required.', 'danger')
            return render_template('report_form.html', user=user)
        if len(name) > 120:
            flash('Name must be 120 characters or fewer.', 'danger')
            return render_template('report_form.html', user=user)
        if len(description) > 1000:
            flash('Description must be 1000 characters or fewer.', 'danger')
            return render_template('report_form.html', user=user)
        report = Report(name=name, description=description, user_id=user.id)
        db.session.add(report)
        db.session.commit()
        flash(f'Report "{name}" created.', 'success')
        return redirect(url_for('view_report', report_id=report.id))
    return render_template('report_form.html', user=user)


@app.route('/reports/<int:report_id>')
@login_required
def view_report(report_id):
    user = current_user()
    report = db.first_or_404(
        db.select(Report).filter_by(id=report_id, user_id=user.id)
    )
    return render_template('report_view.html', user=user, report=report)


@app.route('/reports/<int:report_id>/delete', methods=['POST'])
@login_required
def delete_report(report_id):
    user = current_user()
    report = db.first_or_404(
        db.select(Report).filter_by(id=report_id, user_id=user.id)
    )
    db.session.delete(report)
    db.session.commit()
    flash(f'Report "{report.name}" deleted.', 'info')
    return redirect(url_for('reports'))


# ---------------------------------------------------------------------------
# Widgets
# ---------------------------------------------------------------------------

ALLOWED_WIDGET_TYPES = {'bar', 'line', 'pie', 'doughnut'}

# Maps form key → API path. Only endpoints that return {labels, revenue} are
# supported for generic chart rendering; expand as API shapes are unified.
WIDGET_DATA_SOURCES = {
    'sales_overview':    '/api/sales-overview',
    'revenue_by_region': '/api/revenue-by-region',
    'sales_by_category': '/api/sales-by-category',
    'top_products':      '/api/top-products',
}


@app.route('/dashboards/<int:dashboard_id>/widgets/new', methods=['POST'])
@login_required
def new_widget(dashboard_id):
    user = current_user()
    dashboard = db.first_or_404(
        db.select(Dashboard).filter_by(id=dashboard_id, user_id=user.id)
    )
    title = request.form.get('title', '').strip()
    widget_type = request.form.get('widget_type', '').strip()
    data_source = request.form.get('data_source', '').strip()
    if not title or not widget_type or not data_source:
        flash('Title, type, and data source are all required.', 'danger')
        return redirect(url_for('view_dashboard', dashboard_id=dashboard_id))
    if len(title) > 120:
        flash('Title must be 120 characters or fewer.', 'danger')
        return redirect(url_for('view_dashboard', dashboard_id=dashboard_id))
    if widget_type not in ALLOWED_WIDGET_TYPES:
        flash('Invalid widget type.', 'danger')
        return redirect(url_for('view_dashboard', dashboard_id=dashboard_id))
    if data_source not in WIDGET_DATA_SOURCES:
        flash('Invalid data source.', 'danger')
        return redirect(url_for('view_dashboard', dashboard_id=dashboard_id))
    max_pos = db.session.scalar(
        db.select(func.max(Widget.position)).where(Widget.dashboard_id == dashboard_id)
    ) or 0
    widget = Widget(
        title=title,
        type=widget_type,
        dashboard_id=dashboard.id,
        config=json.dumps({'api_endpoint': WIDGET_DATA_SOURCES[data_source], 'data_source': data_source}),
        position=max_pos + 1,
    )
    db.session.add(widget)
    db.session.commit()
    flash(f'Widget "{title}" added.', 'success')
    return redirect(url_for('view_dashboard', dashboard_id=dashboard_id))


@app.route('/dashboards/<int:dashboard_id>/widgets/<int:widget_id>/delete', methods=['POST'])
@login_required
def delete_widget(dashboard_id, widget_id):
    user = current_user()
    # Ownership check via dashboard
    db.first_or_404(
        db.select(Dashboard).filter_by(id=dashboard_id, user_id=user.id)
    )
    widget = db.first_or_404(
        db.select(Widget).filter_by(id=widget_id, dashboard_id=dashboard_id)
    )
    title = widget.title
    db.session.delete(widget)
    db.session.commit()
    flash(f'Widget "{title}" removed.', 'info')
    return redirect(url_for('view_dashboard', dashboard_id=dashboard_id))


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.route('/api/health')
def api_health():
    """Simple liveness probe; no auth required."""
    try:
        db.session.execute(db.text('SELECT 1'))
        db_ok = True
    except Exception:
        db_ok = False
    status = 'ok' if db_ok else 'degraded'
    return jsonify({'status': status, 'db': db_ok}), 200 if db_ok else 503


# ---------------------------------------------------------------------------
# Analytics API (JSON endpoints for charts)
# ---------------------------------------------------------------------------

@app.route('/api/sales-overview')
@login_required
@limiter.limit('120 per minute; 600 per hour')
def api_sales_overview():
    """Monthly sales totals for the past 12 months.

    NOTE: func.strftime is SQLite-specific. If switching to PostgreSQL,
    replace with func.to_char(Sale.sale_date, 'YYYY-MM').
    """
    twelve_months_ago = datetime.now(timezone.utc) - timedelta(days=365)
    rows = db.session.execute(
        db.select(
            func.strftime('%Y-%m', Sale.sale_date).label('month'),
            func.sum(Sale.total_amount).label('revenue'),
            func.count(Sale.id).label('count'),
        )
        .where(Sale.sale_date >= twelve_months_ago)
        .group_by(func.strftime('%Y-%m', Sale.sale_date))
        .order_by(func.strftime('%Y-%m', Sale.sale_date))
    ).all()
    return jsonify({
        'labels': [r.month for r in rows],
        'revenue': [round(float(r.revenue or 0), 2) for r in rows],
        'count': [r.count for r in rows],
    })


@app.route('/api/revenue-by-region')
@login_required
@limiter.limit('120 per minute; 600 per hour')
def api_revenue_by_region():
    """Total revenue per region."""
    rows = db.session.execute(
        db.select(Region.name, func.sum(Sale.total_amount).label('revenue'))
        .join(Customer, Customer.region_id == Region.id)
        .join(Sale, Sale.customer_id == Customer.id)
        .group_by(Region.id)
        .order_by(func.sum(Sale.total_amount).desc())
    ).all()
    return jsonify({
        'labels': [r.name for r in rows],
        'revenue': [round(float(r.revenue or 0), 2) for r in rows],
    })


@app.route('/api/top-products')
@login_required
@limiter.limit('120 per minute; 600 per hour')
def api_top_products():
    """Top 10 products by revenue."""
    rows = db.session.execute(
        db.select(Product.name, Product.category, func.sum(Sale.total_amount).label('revenue'))
        .join(Sale, Sale.product_id == Product.id)
        .group_by(Product.id)
        .order_by(func.sum(Sale.total_amount).desc())
        .limit(10)
    ).all()
    return jsonify({
        'labels': [r.name for r in rows],
        'revenue': [round(float(r.revenue or 0), 2) for r in rows],
        'categories': [r.category for r in rows],
    })


@app.route('/api/sales-by-category')
@login_required
@limiter.limit('120 per minute; 600 per hour')
def api_sales_by_category():
    """Revenue breakdown by product category."""
    rows = db.session.execute(
        db.select(Product.category, func.sum(Sale.total_amount).label('revenue'))
        .join(Sale, Sale.product_id == Product.id)
        .group_by(Product.category)
        .order_by(func.sum(Sale.total_amount).desc())
    ).all()
    return jsonify({
        'labels': [r.category for r in rows],
        'revenue': [round(float(r.revenue or 0), 2) for r in rows],
    })


@app.route('/api/revenue-targets')
@login_required
@limiter.limit('120 per minute; 600 per hour')
def api_revenue_targets():
    """Quarterly revenue targets per region for the current year."""
    current_year = datetime.now(timezone.utc).year
    targets = db.session.execute(
        db.select(Region.name, RevenueTarget.quarter, RevenueTarget.target_amount)
        .join(Region, RevenueTarget.region_id == Region.id)
        .where(RevenueTarget.year == current_year)
        .order_by(Region.name, RevenueTarget.quarter)
    ).all()
    # Structure: { region: { Q1: target, Q2: target, ... } }
    result = {}
    for region_name, quarter, target in targets:
        result.setdefault(region_name, {})[f'Q{quarter}'] = float(target or 0)
    return jsonify(result)


@app.route('/api/employee-stats')
@login_required
@limiter.limit('120 per minute; 600 per hour')
def api_employee_stats():
    """Headcount and average salary per department."""
    rows = db.session.execute(
        db.select(
            Employee.department,
            func.count(Employee.id).label('headcount'),
            func.avg(Employee.salary).label('avg_salary'),
            func.sum(Employee.salary).label('total_salary'),
        )
        .group_by(Employee.department)
        .order_by(Employee.department)
    ).all()
    return jsonify({
        'departments': [r.department for r in rows],
        'headcount': [r.headcount for r in rows],
        'avg_salary': [round(float(r.avg_salary or 0), 2) for r in rows],
        'total_salary': [round(float(r.total_salary or 0), 2) for r in rows],
    })


@app.route('/api/kpis')
@login_required
@limiter.limit('120 per minute; 600 per hour')
def api_kpis():
    """Key performance indicators."""
    total_revenue = db.session.scalar(db.select(func.sum(Sale.total_amount))) or 0
    total_sales = db.session.scalar(db.select(func.count()).select_from(Sale))
    total_customers = db.session.scalar(db.select(func.count()).select_from(Customer))
    total_products = db.session.scalar(db.select(func.count()).select_from(Product))
    avg_order = float(total_revenue) / total_sales if total_sales else 0

    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    recent_revenue = db.session.scalar(
        db.select(func.sum(Sale.total_amount)).where(Sale.sale_date >= thirty_days_ago)
    ) or 0

    return jsonify({
        'total_revenue': round(float(total_revenue), 2),
        'total_sales': total_sales,
        'total_customers': total_customers,
        'total_products': total_products,
        'avg_order_value': round(avg_order, 2),
        'recent_30d_revenue': round(float(recent_revenue), 2),
    })


@app.route('/api/export/sales')
@login_required
@limiter.limit('10 per minute; 60 per hour')
def api_export_sales():
    """Export all sales as CSV (streamed, no full table load into memory)."""
    rows = db.session.execute(
        db.select(
            Sale.id, Customer.name.label('customer'), Product.name.label('product'),
            Product.category, Sale.quantity, Sale.total_amount, Sale.sale_date,
        )
        .join(Customer, Sale.customer_id == Customer.id)
        .join(Product, Sale.product_id == Product.id)
        .order_by(Sale.sale_date.desc())
    ).all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['id', 'customer', 'product', 'category', 'quantity', 'total_amount', 'sale_date'])
    for r in rows:
        writer.writerow([r.id, r.customer, r.product, r.category, r.quantity,
                         float(r.total_amount), r.sale_date.strftime('%Y-%m-%d %H:%M:%S')])

    filename = f'sales_export_{datetime.now(timezone.utc).strftime("%Y%m%d")}.csv'
    return Response(
        buf.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# App entry point
# ---------------------------------------------------------------------------

def ensure_columns():
    """Add columns introduced after initial deployment (lightweight schema migration).

    SQLAlchemy's create_all() skips tables that already exist, so new columns
    on existing tables must be added manually.  This avoids requiring Alembic
    for a single-file demo app.
    """
    from sqlalchemy import inspect as sa_inspect, text
    with app.app_context():
        inspector = sa_inspect(db.engine)
        if not inspector.has_table('user'):
            return  # create_tables() hasn't run yet; it will create everything
        existing = {col['name'] for col in inspector.get_columns('user')}
        with db.engine.begin() as conn:
            if 'failed_logins' not in existing:
                conn.execute(text(
                    'ALTER TABLE "user" ADD COLUMN failed_logins INTEGER NOT NULL DEFAULT 0'
                ))
                logger.info('Schema migration: added user.failed_logins')
            if 'locked_until' not in existing:
                conn.execute(text(
                    'ALTER TABLE "user" ADD COLUMN locked_until DATETIME'
                ))
                logger.info('Schema migration: added user.locked_until')


def create_tables():
    """Create DB tables and seed the default admin account.

    Called at module load so the app is ready whether started via
    ``python app.py`` or a WSGI server such as gunicorn.
    """
    with app.app_context():
        ensure_columns()  # add any new columns to pre-existing tables
        db.create_all()
        # Create default admin if no users exist.
        # The try/except guards against a rare race condition when multiple
        # worker processes start simultaneously and both attempt the INSERT.
        if not db.session.scalar(db.select(User).limit(1)):
            admin_password = os.environ.get('ADMIN_PASSWORD')
            if not admin_password:
                admin_password = secrets.token_urlsafe(14)
                logger.warning(
                    'ADMIN_PASSWORD env var not set. Generated one-time password: %s  '
                    '(set ADMIN_PASSWORD to control this)',
                    admin_password,
                )
            admin = User(username='admin', email='admin@insightforge.local', is_admin=True)
            admin.set_password(admin_password)
            db.session.add(admin)
            try:
                db.session.commit()
                logger.info('Default admin user created (username: admin)')
            except Exception:
                db.session.rollback()
                logger.info('Admin user already exists (concurrent startup); skipping.')


# Run at module load so tables exist for both `python app.py` and WSGI servers.
create_tables()


if __name__ == '__main__':
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug, host='0.0.0.0', port=5000)
