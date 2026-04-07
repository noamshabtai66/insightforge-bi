/* InsightForge BI — Chart initialization for the overview page */

const COLORS = [
  '#6366f1', '#22c55e', '#f59e0b', '#38bdf8', '#ec4899',
  '#a78bfa', '#34d399', '#fb923c', '#60a5fa', '#f472b6',
];

const CHART_DEFAULTS = {
  responsive: true,
  maintainAspectRatio: true,
  plugins: {
    legend: {
      labels: { color: '#7c87a0', font: { size: 11 } },
    },
    tooltip: {
      backgroundColor: '#1a1d27',
      borderColor: '#2d3250',
      borderWidth: 1,
      titleColor: '#e2e8f0',
      bodyColor: '#7c87a0',
      callbacks: {
        label: (ctx) => ` $${Number(ctx.raw).toLocaleString()}`,
      },
    },
  },
  scales: {
    x: {
      ticks: { color: '#7c87a0', font: { size: 11 } },
      grid: { color: 'rgba(45,50,80,0.6)' },
    },
    y: {
      ticks: {
        color: '#7c87a0',
        font: { size: 11 },
        callback: (v) => '$' + Number(v).toLocaleString(),
      },
      grid: { color: 'rgba(45,50,80,0.6)' },
    },
  },
};

function fmtCurrency(val) {
  if (val >= 1_000_000) return '$' + (val / 1_000_000).toFixed(1) + 'M';
  if (val >= 1_000) return '$' + (val / 1_000).toFixed(1) + 'K';
  return '$' + val.toFixed(2);
}

// Load KPIs
async function loadKPIs() {
  try {
    const res = await fetch('/api/kpis');
    if (!res.ok) return;
    const data = await res.json();
    document.getElementById('kpi-revenue').textContent = fmtCurrency(data.total_revenue);
    document.getElementById('kpi-sales').textContent = data.total_sales.toLocaleString();
    document.getElementById('kpi-customers').textContent = data.total_customers.toLocaleString();
    document.getElementById('kpi-avg-order').textContent = fmtCurrency(data.avg_order_value);
  } catch (e) {
    console.warn('KPI load failed', e);
  }
}

// Monthly revenue line chart
async function initSalesChart() {
  const ctx = document.getElementById('salesChart');
  if (!ctx) return;
  try {
    const res = await fetch('/api/sales-overview');
    if (!res.ok) return;
    const data = await res.json();
    new Chart(ctx, {
      type: 'line',
      data: {
        labels: data.labels,
        datasets: [{
          label: 'Revenue',
          data: data.revenue,
          borderColor: COLORS[0],
          backgroundColor: 'rgba(99,102,241,0.1)',
          fill: true,
          tension: 0.4,
          pointRadius: 3,
          pointHoverRadius: 5,
        }],
      },
      options: { ...CHART_DEFAULTS },
    });
  } catch (e) {
    console.warn('Sales chart failed', e);
  }
}

// Revenue by region doughnut
async function initRegionChart() {
  const ctx = document.getElementById('regionChart');
  if (!ctx) return;
  try {
    const res = await fetch('/api/revenue-by-region');
    if (!res.ok) return;
    const data = await res.json();
    new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: data.labels,
        datasets: [{
          data: data.revenue,
          backgroundColor: COLORS,
          borderColor: '#1a1d27',
          borderWidth: 2,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
          legend: { position: 'right', labels: { color: '#7c87a0', font: { size: 11 } } },
          tooltip: {
            backgroundColor: '#1a1d27',
            borderColor: '#2d3250',
            borderWidth: 1,
            titleColor: '#e2e8f0',
            bodyColor: '#7c87a0',
            callbacks: { label: (ctx) => ` $${Number(ctx.raw).toLocaleString()}` },
          },
        },
      },
    });
  } catch (e) {
    console.warn('Region chart failed', e);
  }
}

// Sales by category pie
async function initCategoryChart() {
  const ctx = document.getElementById('categoryChart');
  if (!ctx) return;
  try {
    const res = await fetch('/api/sales-by-category');
    if (!res.ok) return;
    const data = await res.json();
    new Chart(ctx, {
      type: 'pie',
      data: {
        labels: data.labels,
        datasets: [{
          data: data.revenue,
          backgroundColor: COLORS,
          borderColor: '#1a1d27',
          borderWidth: 2,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
          legend: { position: 'right', labels: { color: '#7c87a0', font: { size: 11 } } },
          tooltip: {
            backgroundColor: '#1a1d27',
            borderColor: '#2d3250',
            borderWidth: 1,
            titleColor: '#e2e8f0',
            bodyColor: '#7c87a0',
            callbacks: { label: (ctx) => ` $${Number(ctx.raw).toLocaleString()}` },
          },
        },
      },
    });
  } catch (e) {
    console.warn('Category chart failed', e);
  }
}

// Top products horizontal bar
async function initProductsChart() {
  const ctx = document.getElementById('productsChart');
  if (!ctx) return;
  try {
    const res = await fetch('/api/top-products');
    if (!res.ok) return;
    const data = await res.json();
    new Chart(ctx, {
      type: 'bar',
      data: {
        labels: data.labels,
        datasets: [{
          label: 'Revenue',
          data: data.revenue,
          backgroundColor: COLORS.map((c) => c + 'cc'),
          borderColor: COLORS,
          borderWidth: 1,
        }],
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#1a1d27',
            borderColor: '#2d3250',
            borderWidth: 1,
            titleColor: '#e2e8f0',
            bodyColor: '#7c87a0',
            callbacks: { label: (ctx) => ` $${Number(ctx.raw).toLocaleString()}` },
          },
        },
        scales: {
          x: {
            ticks: {
              color: '#7c87a0',
              font: { size: 10 },
              callback: (v) => '$' + Number(v).toLocaleString(),
            },
            grid: { color: 'rgba(45,50,80,0.6)' },
          },
          y: {
            ticks: { color: '#7c87a0', font: { size: 11 } },
            grid: { display: false },
          },
        },
      },
    });
  } catch (e) {
    console.warn('Products chart failed', e);
  }
}

// Quarterly revenue targets grouped bar chart
async function initRevenueTargetsChart() {
  const ctx = document.getElementById('targetsChart');
  if (!ctx) return;
  try {
    const res = await fetch('/api/revenue-targets');
    if (!res.ok) return;
    const data = await res.json();
    const regions = Object.keys(data);
    if (!regions.length) return;
    const quarters = ['Q1', 'Q2', 'Q3', 'Q4'];
    const datasets = regions.map((region, i) => ({
      label: region,
      data: quarters.map((q) => data[region][q] || 0),
      backgroundColor: COLORS[i % COLORS.length] + 'aa',
      borderColor: COLORS[i % COLORS.length],
      borderWidth: 1,
    }));
    new Chart(ctx, {
      type: 'bar',
      data: { labels: quarters, datasets },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
          legend: { labels: { color: '#7c87a0', font: { size: 11 } } },
          tooltip: {
            backgroundColor: '#1a1d27',
            borderColor: '#2d3250',
            borderWidth: 1,
            titleColor: '#e2e8f0',
            bodyColor: '#7c87a0',
            callbacks: { label: (ctx) => ` ${ctx.dataset.label}: $${Number(ctx.raw).toLocaleString()}` },
          },
        },
        scales: {
          x: { ticks: { color: '#7c87a0', font: { size: 11 } }, grid: { color: 'rgba(45,50,80,0.6)' } },
          y: {
            ticks: {
              color: '#7c87a0',
              font: { size: 11 },
              callback: (v) => '$' + Number(v / 1_000_000).toFixed(1) + 'M',
            },
            grid: { color: 'rgba(45,50,80,0.6)' },
          },
        },
      },
    });
  } catch (e) {
    console.warn('Revenue targets chart failed', e);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  loadKPIs();
  initSalesChart();
  initRegionChart();
  initCategoryChart();
  initProductsChart();
  initRevenueTargetsChart();
});
