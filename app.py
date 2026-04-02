import os
import sys
import json
from datetime import datetime, timedelta, timezone
from functools import wraps

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from flask import (
    Flask, redirect, url_for, session, request,
    render_template, flash, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func

from models.models import (
    db, User, DataSource, Dashboard, Widget, Report,
    Region, Product, Customer, Sale, Employee, RevenueTarget
)

app = Flask(__name__)
_secret = os.environ.get('SECRET_KEY', 'dev-secret-change-in-production')
if _secret == 'dev-secret-change-in-production':
    print('WARNING: Using default SECRET_KEY. Set the SECRET_KEY environment variable in production.', file=sys.stderr)
app.config['SECRET_KEY'] = _secret
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 'sqlite:///insightforge.db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

db.init_app(app)


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
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'"
    )
    return response


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, message='Page not found.'), 404


@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', code=500, message='Internal server error.'), 500


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        # Guard against stale session (user deleted after login)
        user = db.session.get(User, session['user_id'])
        if user is None:
            session.clear()
            flash('Your session has expired. Please log in again.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def current_user():
    if 'user_id' in session:
        return db.session.get(User, session['user_id'])
    return None


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash('Username and password are required.', 'danger')
            return render_template('login.html')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('index'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
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
        elif not password or len(password) < 6:
            error = 'Password must be at least 6 characters.'
        elif password != confirm:
            error = 'Passwords do not match.'
        elif User.query.filter_by(username=username).first():
            error = 'Username already taken.'
        elif email and User.query.filter_by(email=email).first():
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


@app.route('/logout')
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
    total_sales = Sale.query.count()
    total_revenue = db.session.query(func.sum(Sale.total_amount)).scalar() or 0
    total_customers = Customer.query.count()
    total_products = Product.query.count()

    # Recent sales (last 30 days)
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    recent_sales = Sale.query.filter(Sale.sale_date >= thirty_days_ago).count()

    # Top 5 products by revenue
    top_products = (
        db.session.query(Product.name, func.sum(Sale.total_amount).label('revenue'))
        .join(Sale, Sale.product_id == Product.id)
        .group_by(Product.id)
        .order_by(func.sum(Sale.total_amount).desc())
        .limit(5)
        .all()
    )

    dashboards = Dashboard.query.filter_by(user_id=user.id).order_by(Dashboard.created_at.desc()).limit(5).all()
    reports = Report.query.filter_by(user_id=user.id).order_by(Report.created_at.desc()).limit(5).all()

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
    )


# ---------------------------------------------------------------------------
# Dashboards
# ---------------------------------------------------------------------------

@app.route('/dashboards')
@login_required
def dashboards():
    user = current_user()
    all_dashboards = Dashboard.query.filter_by(user_id=user.id).order_by(Dashboard.created_at.desc()).all()
    return render_template('dashboards.html', user=user, dashboards=all_dashboards)


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
    dashboard = Dashboard.query.filter_by(id=dashboard_id, user_id=user.id).first_or_404()
    widgets = Widget.query.filter_by(dashboard_id=dashboard_id).order_by(Widget.position).all()
    return render_template('dashboard_view.html', user=user, dashboard=dashboard, widgets=widgets)


@app.route('/dashboards/<int:dashboard_id>/delete', methods=['POST'])
@login_required
def delete_dashboard(dashboard_id):
    user = current_user()
    dashboard = Dashboard.query.filter_by(id=dashboard_id, user_id=user.id).first_or_404()
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
    sources = DataSource.query.filter_by(user_id=user.id).order_by(DataSource.created_at.desc()).all()
    return render_template('data_sources.html', user=user, sources=sources)


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
    source = DataSource.query.filter_by(id=source_id, user_id=user.id).first_or_404()
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
    all_reports = Report.query.filter_by(user_id=user.id).order_by(Report.created_at.desc()).all()
    return render_template('reports.html', user=user, reports=all_reports)


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
        report = Report(name=name, description=description, user_id=user.id)
        db.session.add(report)
        db.session.commit()
        flash(f'Report "{name}" created.', 'success')
        return redirect(url_for('reports'))
    return render_template('report_form.html', user=user)


@app.route('/reports/<int:report_id>')
@login_required
def view_report(report_id):
    user = current_user()
    report = Report.query.filter_by(id=report_id, user_id=user.id).first_or_404()
    return render_template('report_view.html', user=user, report=report)


@app.route('/reports/<int:report_id>/delete', methods=['POST'])
@login_required
def delete_report(report_id):
    user = current_user()
    report = Report.query.filter_by(id=report_id, user_id=user.id).first_or_404()
    db.session.delete(report)
    db.session.commit()
    flash(f'Report "{report.name}" deleted.', 'info')
    return redirect(url_for('reports'))


# ---------------------------------------------------------------------------
# Analytics API (JSON endpoints for charts)
# ---------------------------------------------------------------------------

@app.route('/api/sales-overview')
@login_required
def api_sales_overview():
    """Monthly sales totals for the past 12 months."""
    twelve_months_ago = datetime.now(timezone.utc) - timedelta(days=365)
    rows = (
        db.session.query(
            func.strftime('%Y-%m', Sale.sale_date).label('month'),
            func.sum(Sale.total_amount).label('revenue'),
            func.count(Sale.id).label('count'),
        )
        .filter(Sale.sale_date >= twelve_months_ago)
        .group_by(func.strftime('%Y-%m', Sale.sale_date))
        .order_by(func.strftime('%Y-%m', Sale.sale_date))
        .all()
    )
    return jsonify({
        'labels': [r.month for r in rows],
        'revenue': [round(r.revenue or 0, 2) for r in rows],
        'count': [r.count for r in rows],
    })


@app.route('/api/revenue-by-region')
@login_required
def api_revenue_by_region():
    """Total revenue per region."""
    rows = (
        db.session.query(Region.name, func.sum(Sale.total_amount).label('revenue'))
        .join(Customer, Customer.region_id == Region.id)
        .join(Sale, Sale.customer_id == Customer.id)
        .group_by(Region.id)
        .order_by(func.sum(Sale.total_amount).desc())
        .all()
    )
    return jsonify({
        'labels': [r.name for r in rows],
        'revenue': [round(r.revenue or 0, 2) for r in rows],
    })


@app.route('/api/top-products')
@login_required
def api_top_products():
    """Top 10 products by revenue."""
    rows = (
        db.session.query(Product.name, Product.category, func.sum(Sale.total_amount).label('revenue'))
        .join(Sale, Sale.product_id == Product.id)
        .group_by(Product.id)
        .order_by(func.sum(Sale.total_amount).desc())
        .limit(10)
        .all()
    )
    return jsonify({
        'labels': [r.name for r in rows],
        'revenue': [round(r.revenue or 0, 2) for r in rows],
        'categories': [r.category for r in rows],
    })


@app.route('/api/sales-by-category')
@login_required
def api_sales_by_category():
    """Revenue breakdown by product category."""
    rows = (
        db.session.query(Product.category, func.sum(Sale.total_amount).label('revenue'))
        .join(Sale, Sale.product_id == Product.id)
        .group_by(Product.category)
        .order_by(func.sum(Sale.total_amount).desc())
        .all()
    )
    return jsonify({
        'labels': [r.category for r in rows],
        'revenue': [round(r.revenue or 0, 2) for r in rows],
    })


@app.route('/api/kpis')
@login_required
def api_kpis():
    """Key performance indicators."""
    total_revenue = db.session.query(func.sum(Sale.total_amount)).scalar() or 0
    total_sales = Sale.query.count()
    total_customers = Customer.query.count()
    total_products = Product.query.count()
    avg_order = total_revenue / total_sales if total_sales else 0

    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    recent_revenue = db.session.query(func.sum(Sale.total_amount)).filter(
        Sale.sale_date >= thirty_days_ago
    ).scalar() or 0

    return jsonify({
        'total_revenue': round(total_revenue, 2),
        'total_sales': total_sales,
        'total_customers': total_customers,
        'total_products': total_products,
        'avg_order_value': round(avg_order, 2),
        'recent_30d_revenue': round(recent_revenue, 2),
    })


# ---------------------------------------------------------------------------
# App entry point
# ---------------------------------------------------------------------------

def create_tables():
    with app.app_context():
        db.create_all()
        # Create default admin if no users exist
        if not User.query.first():
            admin = User(username='admin', email='admin@insightforge.local', is_admin=True)
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print('Default admin user created: admin / admin123')


if __name__ == '__main__':
    create_tables()
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug, host='0.0.0.0', port=5000)
