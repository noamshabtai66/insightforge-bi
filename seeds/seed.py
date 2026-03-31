"""Seed the InsightForge BI database with sample data.

Run from the project root:
    python -m seeds.seed
"""

import random
import sys
import os
from datetime import datetime, timedelta

# Ensure project root is on the path when run directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db
from models.models import (
    Product, Customer, Sale, Region, Employee, RevenueTarget
)


def create_sample_data():
    # Guard: skip if already seeded
    if Region.query.first():
        print("Database already seeded — skipping.")
        return

    print("Seeding regions...")
    region_names = ['North America', 'Europe', 'Asia', 'South America', 'Africa']
    regions = []
    for name in region_names:
        r = Region(name=name)
        db.session.add(r)
        regions.append(r)
    db.session.flush()  # get IDs without committing

    print("Seeding products...")
    categories = ['Electronics', 'Clothing', 'Home Goods', 'Books', 'Toys']
    products = []
    for i in range(50):
        p = Product(
            name=f'Product {i + 1}',
            category=random.choice(categories),
            price=round(random.uniform(10, 500), 2),
        )
        db.session.add(p)
        products.append(p)
    db.session.flush()

    print("Seeding customers...")
    customers = []
    for i in range(200):
        c = Customer(
            name=f'Customer {i + 1}',
            email=f'customer{i + 1}@example.com',
            region_id=random.choice(regions).id,
        )
        db.session.add(c)
        customers.append(c)
    db.session.flush()

    print("Seeding sales (5 000 records)...")
    start_date = datetime(2021, 1, 1)
    for _ in range(5000):
        product = random.choice(products)
        quantity = random.randint(1, 5)
        sale = Sale(
            customer_id=random.choice(customers).id,
            product_id=product.id,
            quantity=quantity,
            total_amount=round(product.price * quantity, 2),
            sale_date=start_date + timedelta(days=random.randint(0, 730)),
        )
        db.session.add(sale)

    print("Seeding employees...")
    departments = ['Sales', 'Marketing', 'Engineering', 'HR']
    for i in range(20):
        e = Employee(
            name=f'Employee {i + 1}',
            department=random.choice(departments),
            salary=round(random.uniform(50000, 150000), 2),
        )
        db.session.add(e)

    print("Seeding revenue targets...")
    db.session.flush()  # ensure region IDs are available
    for region in Region.query.all():
        for quarter in range(1, 5):
            t = RevenueTarget(
                region_id=region.id,
                quarter=quarter,
                year=2024,
                target_amount=random.randint(500000, 2000000),
            )
            db.session.add(t)

    db.session.commit()
    print("Seed complete.")


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        try:
            create_sample_data()
        except Exception as exc:
            db.session.rollback()
            print(f"Seed failed: {exc}", file=sys.stderr)
            sys.exit(1)
