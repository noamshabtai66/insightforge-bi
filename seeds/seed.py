import random
from datetime import datetime, timedelta
from models.models import db, Product, Customer, Sale, Region, Employee, RevenueTarget

# Create sample data
def create_sample_data():
    # Create regions
    regions = ['North America', 'Europe', 'Asia', 'South America', 'Africa']
    for region_name in regions:
        region = Region(name=region_name)
        db.session.add(region)

    # Create products
    categories = ['Electronics', 'Clothing', 'Home Goods', 'Books', 'Toys']
    for i in range(50):
        product = Product(
            name=f'Product {i+1}',
            category=random.choice(categories),
            price=round(random.uniform(10, 500), 2)
        )
        db.session.add(product)

    # Create customers
    for i in range(200):
        customer = Customer(
            name=f'Customer {i+1}',
            email=f'customer{i+1}@example.com',
            region_id=random.randint(1, 5)
        )
        db.session.add(customer)

    # Create sales
    start_date = datetime(2021, 1, 1)
    for i in range(5000):
        sale_date = start_date + timedelta(days=random.randint(0, 730))
        sale = Sale(
            customer_id=random.randint(1, 200),
            product_id=random.randint(1, 50),
            quantity=random.randint(1, 5),
            sale_date=sale_date
        )
        db.session.add(sale)

    # Create employees
    departments = ['Sales', 'Marketing', 'Engineering', 'HR']
    for i in range(20):
        employee = Employee(
            name=f'Employee {i+1}',
            department=random.choice(departments),
            salary=round(random.uniform(50000, 150000), 2)
        )
        db.session.add(employee)

    # Create revenue targets
    for region in Region.query.all():
        for quarter in range(1, 5):
            target = RevenueTarget(
                region_id=region.id,
                quarter=quarter,
                target_amount=random.randint(500000, 2000000)
            )
            db.session.add(target)

    db.session.commit()