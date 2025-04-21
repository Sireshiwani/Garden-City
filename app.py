import io
import click
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import pandas as pd
from models import db, User, Sale, Expense
from flask_wtf.csrf import CSRFProtect
import os
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, validators


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///barbershop.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
Bootstrap(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'auth.login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Create tables
with app.app_context():
    db.create_all()


# Custom filter for currency formatting
@app.template_filter('currency')
def currency_format(value):
    return f"Ksh{value:,.2f}"


# Routes
class AdminCreationForm(FlaskForm):
    email = StringField('Email', validators=[validators.DataRequired(), validators.Email()])
    password = PasswordField('Password', validators=[validators.DataRequired(), validators.Length(min=8)])


@app.route('/create-first-admin', methods=['GET', 'POST'])
def create_first_admin():
    if not User.query.filter_by(email='james@gcfc.com').first():
        admin = User(
            username='admin',
            email='james@gcfc.com',
            password=generate_password_hash('admin!234', method='pbkdf2:sha256:600000'),
            is_admin=True,
            is_active=True
        )
        db.session.add(admin)
        db.session.commit()
        print("Admin user created!")
    else:
        print("Admin user already exists!")
    return "Script executed", 200


@app.route('/')
def home():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('add_sale'))
    return redirect(url_for('login'))


# Auth routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        flash('Invalid email or password', 'danger')
    return render_template('auth/login.html')


@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    if not current_user.is_admin:
        flash('Only admins can register new users', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        is_admin = True if request.form.get('is_admin') == 'on' else False

        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('register'))

        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password, method='pbkdf2:sha256:600000'),
            is_admin=is_admin
        )
        db.session.add(new_user)
        db.session.commit()
        flash('User registered successfully!', 'success')
        return redirect(url_for('manage_staff'))

    return render_template('auth/register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))


# Sales routes
@app.route('/sales/add', methods=['GET', 'POST'])
@login_required
def add_sale():
    all_staff = User.query.all()

    if request.method == 'POST':
        amount = float(request.form.get('amount'))
        category = request.form.get('category')
        customer_name = request.form.get('notes')
        staff_name = request.form.get('staff')
        payment_input = request.form.get('payment')
        user = db.one_or_404(db.select(User).filter_by(username=staff_name),
                             description=f"No user named '{staff_name}'."
                             )

        print(customer_name)
        new_sale = Sale(
            amount=amount,
            category=category,
            staff_id=user.id,
            customer_name=customer_name,
            payment_mode=payment_input
        )
        db.session.add(new_sale)
        db.session.commit()
        flash('Sale recorded successfully!', 'success')
        return redirect(url_for('add_sale'))

    return render_template('transactions/sales.html', all_staff=all_staff)


# Expenses routes
@app.route('/expenses/add', methods=['GET', 'POST'])
@login_required
def add_expense():
    # if not current_user.is_admin:
    #     flash('Only admins can add expenses', 'danger')
    #     return redirect(url_for('home'))


    if request.method == 'POST':
        amount = float(request.form.get('amount'))
        category = request.form.get('category')
        description = request.form.get('description')

        new_expense = Expense(
            amount=amount,
            category=category,
            description=description
        )
        db.session.add(new_expense)
        db.session.commit()
        flash('Expense recorded successfully!', 'success')
        return redirect(url_for('add_expense'))

    return render_template('transactions/expenses.html')


# Admin routes
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('home'))

    # Calculate totals for dashboard
    today = datetime.utcnow().date()
    week_ago = today - timedelta(days=7)
    month_ago = today - timedelta(days=30)

    # Sales data
    total_sales = db.session.query(db.func.sum(Sale.amount)).scalar() or 0
    today_sales = db.session.query(db.func.sum(Sale.amount)).filter(
        db.func.date(Sale.date) == today
    ).scalar() or 0
    weekly_sales = db.session.query(db.func.sum(Sale.amount)).filter(
        db.func.date(Sale.date) >= week_ago
    ).scalar() or 0

    # Expenses data
    total_expenses = db.session.query(db.func.sum(Expense.amount)).scalar() or 0
    monthly_expenses = db.session.query(db.func.sum(Expense.amount)).filter(
        db.func.date(Expense.date) >= month_ago
    ).scalar() or 0

    # Staff performance (top 5)
    staff_performance = db.session.query(
        User.username,
        db.func.sum(Sale.amount).label('total_sales'),
        db.func.count(Sale.id).label('sales_count')
    ).join(Sale).group_by(User.id).order_by(db.desc('total_sales')).limit(5).all()

    return render_template('admin/dashboard.html',
                           total_sales=total_sales,
                           today_sales=today_sales,
                           weekly_sales=weekly_sales,
                           total_expenses=total_expenses,
                           monthly_expenses=monthly_expenses,
                           staff_performance=staff_performance)


@app.route('/admin/staff')
@login_required
def manage_staff():
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('home'))

    staff_list = User.query.all()
    return render_template('admin/staff.html', staff_list=staff_list)


@app.route('/admin/reports', methods=['GET', 'POST'])
@login_required
def generate_reports():
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('home'))

    # Default report - last 30 days sales by category
    start_date = (datetime.utcnow() - timedelta(days=30)).strftime('%Y-%m-%d')
    end_date = datetime.utcnow().strftime('%Y-%m-%d')

    if request.method == 'POST':
        report_type = request.form.get('report_type')
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')

        # Convert to datetime objects for filtering
        start_dt = datetime.strptime(start_date, '%Y-%m-%d')
        end_dt = datetime.strptime(end_date, '%Y-%m-%d')

        if report_type == 'sales_by_category':
            results = db.session.query(
                Sale.category,
                db.func.sum(Sale.amount).label('total_sales'),
                db.func.count(Sale.id).label('transaction_count')
            ).filter(
                db.func.date(Sale.date) >= start_dt,
                db.func.date(Sale.date) <= end_dt
            ).group_by(Sale.category).all()

            return render_template('admin/reports.html',
                                   report_type=report_type,
                                   results=results,
                                   start_date=start_date,
                                   end_date=end_date)

        elif report_type == 'sales_by_staff':
            results = db.session.query(
                User.username,
                db.func.sum(Sale.amount).label('total_sales'),
                db.func.count(Sale.id).label('transaction_count')
            ).join(Sale).filter(
                db.func.date(Sale.date) >= start_dt,
                db.func.date(Sale.date) <= end_dt
            ).group_by(User.id).all()

            return render_template('admin/reports.html',
                                   report_type=report_type,
                                   results=results,
                                   start_date=start_date,
                                   end_date=end_date)

        elif report_type == 'expenses_by_category':
            results = db.session.query(
                Expense.category,
                db.func.sum(Expense.amount).label('total_expenses'),
                db.func.count(Expense.id).label('transaction_count')
            ).filter(
                db.func.date(Expense.date) >= start_dt,
                db.func.date(Expense.date) <= end_dt
            ).group_by(Expense.category).all()

            return render_template('admin/reports.html',
                                   report_type=report_type,
                                   results=results,
                                   start_date=start_date,
                                   end_date=end_date)

    return render_template('admin/reports.html',
                           start_date=start_date,
                           end_date=end_date)


@app.route('/admin/reports/export')
@login_required
def export_report():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    report_type = request.args.get('type')
    start_date = request.args.get('start')
    end_date = request.args.get('end')

    start_dt = datetime.strptime(start_date, '%Y-%m-%d')
    end_dt = datetime.strptime(end_date, '%Y-%m-%d')

    if report_type == 'sales_by_category':
        results = db.session.query(
            Sale.category,
            db.func.sum(Sale.amount).label('total_sales'),
            db.func.count(Sale.id).label('transaction_count')
        ).filter(
            db.func.date(Sale.date) >= start_dt,
            db.func.date(Sale.date) <= end_dt
        ).group_by(Sale.category).all()

        df = pd.DataFrame([(r.category, r.total_sales, r.transaction_count) for r in results],
                          columns=['Category', 'Total Sales', 'Transaction Count'])

    elif report_type == 'sales_by_staff':
        results = db.session.query(
            User.username,
            db.func.sum(Sale.amount).label('total_sales'),
            db.func.count(Sale.id).label('transaction_count')
        ).join(Sale).filter(
            db.func.date(Sale.date) >= start_dt,
            db.func.date(Sale.date) <= end_dt
        ).group_by(User.id).all()

        df = pd.DataFrame([(r.username, r.total_sales, r.transaction_count) for r in results],
                          columns=['Staff', 'Total Sales', 'Transaction Count'])

    elif report_type == 'expenses_by_category':
        results = db.session.query(
            Expense.category,
            db.func.sum(Expense.amount).label('total_expenses'),
            db.func.count(Expense.id).label('transaction_count')
        ).filter(
            db.func.date(Expense.date) >= start_dt,
            db.func.date(Expense.date) <= end_dt
        ).group_by(Expense.category).all()

        df = pd.DataFrame([(r.category, r.total_expenses, r.transaction_count) for r in results],
                          columns=['Category', 'Total Expenses', 'Transaction Count'])

    else:
        return jsonify({'error': 'Invalid report type'}), 400

    # Create Excel file
    output = io.BytesIO()
    writer = pd.ExcelWriter(output, engine='xlsxwriter')
    df.to_excel(writer, sheet_name='Report', index=False)
    writer.close()
    output.seek(0)

    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=f'report_{report_type}_{start_date}_to_{end_date}.xlsx'
    )


@app.route('/admin/staff/<int:staff_id>')
@login_required
def view_staff(staff_id):
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('home'))

    staff = User.query.get_or_404(staff_id)
    return render_template('admin/view_staff.html', staff=staff)


@app.route('/admin/staff/<int:staff_id>/delete', methods=['POST'])
@login_required
def delete_staff(staff_id):
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('home'))

    staff = User.query.get_or_404(staff_id)

    # Prevent deleting yourself
    if staff.id == current_user.id:
        flash('You cannot deactivate your own account!', 'danger')
        return redirect(url_for('view_staff', staff_id=staff_id))

    # Delete associated sales first (if needed)
    Sale.query.filter_by(staff_id=staff_id).delete()

    staff.is_active = False
    db.session.commit()
    flash('Staff member deactivated', 'success')
    return redirect(url_for('manage_staff'))


@app.route('/admin/staff/<int:staff_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_staff(staff_id):
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('home'))

    staff = User.query.get_or_404(staff_id)

    if request.method == 'POST':
        staff.username = request.form.get('username')
        staff.email = request.form.get('email')
        staff.is_admin = True if request.form.get('is_admin') == 'on' else False

        if request.form.get('password'):
            staff.password = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256:600000')

        # In your edit_staff route
        if User.query.filter(User.email == request.form.get('email'), User.id != staff.id).first():
            flash('Email already in use by another account', 'danger')
            return redirect(url_for('edit_staff', staff_id=staff.id))
        db.session.commit()
        flash('Staff updated successfully!', 'success')
        return redirect(url_for('view_staff', staff_id=staff.id))

    return render_template('admin/edit_staff.html', staff=staff)


@app.route('/admin/reports/staff-sales', methods=['GET', 'POST'])
@login_required
def staff_sales_report():
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('home'))

    # Default to last 30 days
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=30)

    if request.method == 'POST':
        start_date = datetime.strptime(request.form.get('start_date'), '%Y-%m-%d')
        end_date = datetime.strptime(request.form.get('end_date'), '%Y-%m-%d')
        staff_id = request.form.get('staff_id')

    # Base query
    query = db.session.query(
        User.username.label('staff_name'),
        Sale.date.label('sale_date'),
        Sale.amount,
        Sale.category,
        Sale.customer_name
    ).join(User)

    # Apply filters
    if request.method == 'POST':
        query = query.filter(Sale.date >= start_date, Sale.date <= end_date)
        if staff_id and staff_id != 'all':
            query = query.filter(Sale.staff_id == staff_id)

    results = query.order_by(User.username, Sale.date.desc()).all()

    # Calculate totals
    total_sales = sum(sale.amount for sale in results) if results else 0

    # Get staff for dropdown
    staff_list = User.query.order_by(User.username).all()

    return render_template('admin/staff_sales_report.html',
                           results=results,
                           total_sales=total_sales,
                           staff_list=staff_list,
                           start_date=start_date.date(),
                           end_date=end_date.date(),
                           selected_staff=request.form.get('staff_id', 'all'))


@app.route('/admin/reports/export-staff-sales')
@login_required
def export_staff_sales():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    start_date = datetime.strptime(request.args.get('start'), '%Y-%m-%d')
    end_date = datetime.strptime(request.args.get('end'), '%Y-%m-%d')
    staff_id = request.args.get('staff_id', 'all')

    # Same query as the report
    query = db.session.query(
        User.username.label('Staff'),
        Sale.date.label('Date'),
        Sale.amount.label('Amount'),
        Sale.category.label('Category'),
        Sale.customer_name.label('Customer')
    ).join(User).filter(
        Sale.date >= start_date,
        Sale.date <= end_date
    )

    if staff_id != 'all':
        query = query.filter(Sale.staff_id == staff_id)

    results = query.order_by(User.username, Sale.date.desc()).all()

    # Create DataFrame
    df = pd.DataFrame([(
        r.Staff,
        r.Date.strftime('%d-%B-%Y %H:%M'),
        r.Amount,
        r.Category,
        r.Customer or ''
    ) for r in results], columns=['Staff', 'Date', 'Amount', 'Category', 'Customer'])

    # Create Excel file
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, sheet_name='Staff Sales', index=False)

        # Formatting
        workbook = writer.book
        worksheet = writer.sheets['Staff Sales']

        # Format headers
        header_format = workbook.add_format({
            'bold': True,
            'text_wrap': True,
            'valign': 'top',
            'fg_color': '#4472C4',
            'font_color': 'white',
            'border': 1
        })

        for col_num, value in enumerate(df.columns.values):
            worksheet.write(0, col_num, value, header_format)

        # Format currency
        money_format = workbook.add_format({'num_format': '$#,##0.00'})
        worksheet.set_column('C:C', 12, money_format)

        # Format dates
        date_format = workbook.add_format({'num_format': 'yyyy-mm-dd hh:mm'})
        worksheet.set_column('B:B', 18, date_format)

        # Auto-adjust columns
        for i, width in enumerate(get_col_widths(df)):
            worksheet.set_column(i, i, width)

    output.seek(0)

    filename = f"staff_sales_{start_date.date()}_to_{end_date.date()}"
    if staff_id != 'all':
        staff = User.query.get(staff_id)
        filename += f"_{staff.username}"

    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=f'{filename}.xlsx'
    )


def get_col_widths(df):
    return [max([len(str(s)) for s in df[col].values] + [len(str(col))]) for col in df.columns]


@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}


@app.cli.command("create-admin")
@click.argument("email")
@click.argument("password")
def create_admin(email, password):
    """Create an admin user."""
    if User.query.filter_by(email=email).first():
        print("User already exists!")
        return

    admin = User(
        username="admin",
        email='admin@demo.com',
        password=generate_password_hash(password, method='Sha256'),
        is_admin=True
    )
    db.session.add(admin)
    db.session.commit()
    print("Admin user created successfully!")

if __name__ == '__main__':
    app.run(debug=False)
