import io
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, send_file, session, make_response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import pandas as pd
from models import db, User, Sale, Expense
from flask_wtf.csrf import CSRFProtect
import os
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, validators, FloatField, DateTimeLocalField, TextAreaField
from forms import SalesQueryForm
import csv
from flask_migrate import Migrate


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///barbershop.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# Initialize extensions
db.init_app(app)
Bootstrap(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.init_app(app)


# Set session lifetime (e.g., 3 minutes of inactivity)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=3)


@app.before_request
def before_request():
    # Reset session timeout on each request
    session.permanent = True
    session.modified = True  # Mark session as modified to extend timeout

app.config['SESSION_PERMANENT'] = False  # Session ends when browser closes


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create tables
with app.app_context():
    db.create_all()

# migrate db
migrate = Migrate(app, db)


# Custom filter for currency formatting
@app.template_filter('currency')
def currency_format(value):
    return f"Ksh{value:,.2f}"

# Date Validator
def validate_entry_date(date_str):
    try:
        entry_date = datetime.strptime(date_str, '%Y-%m-%d')
        if entry_date > datetime.utcnow():
            flash("Future dates are not allowed", 'danger')
            return False
        else:
            return entry_date
    except ValueError:
        flash("Invalid date format", 'danger')
        return False


# Edit Sale Form
class EditSaleForm(FlaskForm):
    amount = FloatField('Amount', validators=[validators.InputRequired()])
    category = StringField('Category', validators=[validators.InputRequired()])
    date = DateTimeLocalField('Date', format='%Y-%m-%d', validators=[validators.InputRequired()])
    customer_name = TextAreaField('Customer Name')

# Admin Creation Form
class AdminCreationForm(FlaskForm):
    email = StringField('Email', validators=[validators.DataRequired(), validators.Email()])
    password = PasswordField('Password', validators=[validators.DataRequired(), validators.Length(min=8)])


# Routes
# Admin creator
@app.route('/create-first-admin', methods=['GET', 'POST'])
def create_first_admin():
    from models import User, db
    admin = User.query.filter_by(email='james@gcfc.com').first()
    if not admin:
        admin = User(
            username='admin',
            email='james@gcfc.com',
            password=generate_password_hash('admin!234', method='pbkdf2:sha256:600000'),
            is_admin=True,
            is_active=True
        )
        db.session.add(admin)
        db.session.commit()

    return ("Admin Created")



@app.route('/test-db')
def test_db():
    try:
        db.engine.connect()
        return "Database connection successful!", 200
    except Exception as e:
        return f"Connection failed: {str(e)}", 500


@app.route('/')
def home():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        if current_user.username == 'Nicole':
            return redirect(url_for('staff_sales_report'))
        return redirect(url_for('my_sales'))
    return redirect(url_for('login', now=datetime.now()))


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
    return render_template('auth/login.html', now=datetime.now())


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

    return render_template('auth/register.html', now=datetime.now())

@app.route('/ping')
def ping():
    # Just updates session by accessing it
    session.modified = True
    return '', 204


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login', now=datetime.now()))


# Sales routes
@app.route('/sales/add', methods=['GET', 'POST'])
@login_required
def add_sale():
    if current_user.id > 3:
        flash('Only admins can add sales', 'danger')
        return redirect(url_for('home'))


    all_staff = User.query.all()

    if request.method == 'POST':
        date_str = request.form['sale_date']
        # sale_date = validate_entry_date(date_str)
        if validate_entry_date(date_str):
            amount = float(request.form.get('amount'))
            category = request.form.get('category')
            customer_name = request.form.get('notes')
            staff_name = request.form.get('staff')
            payment_input = request.form.get('payment')
            date = datetime.strptime(date_str, '%Y-%m-%d')
            user = db.one_or_404(db.select(User).filter_by(username=staff_name),
                                 description=f"No user named '{staff_name}'."
                                 )

            new_sale = Sale(
                amount=amount,
                category=category,
                staff_id=user.id,
                customer_name=customer_name,
                payment_mode=payment_input,
                date=date
            )

            db.session.add(new_sale)
            db.session.commit()
            flash('Sale recorded successfully!', 'success')
            return redirect(url_for('add_sale'))
        else:
            return redirect(url_for("add_sale"))

    return render_template('transactions/sales.html', all_staff=all_staff, now=datetime.now())


# Expenses routes
@app.route('/expenses/add', methods=['GET', 'POST'])
@login_required
def add_expense():
    if current_user.id > 3:
        flash('Only admins can add expenses', 'danger')
        return redirect(url_for('home'))


    expense_date = datetime.utcnow().strftime('%Y-%m-%d')
    if request.method == 'POST':
        if request.method == 'POST':
            try:
                date_str = request.form['expense_date']
                expense_date = validate_entry_date(date_str)
            except ValueError:
                expense_date = datetime.utcnow()

        amount = float(request.form.get('amount'))
        category = request.form.get('category')
        description = request.form.get('description')

        new_expense = Expense(
            amount=amount,
            category=category,
            description=description,
            date = expense_date
        )
        db.session.add(new_expense)
        db.session.commit()
        flash('Expense recorded successfully!', 'success')
        return redirect(url_for('add_expense'))

    return render_template('transactions/expenses.html', date=expense_date, now=datetime.now())


# Admin routes
@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('home'))

    # Calculate totals for dashboard
    today = datetime.today().date()
    week_ago = today - timedelta(days=7)
    date_num = today.strftime("%d")
    month_ago = today - timedelta(days=int(date_num) - 1)

    # Sales data
    total_sales = db.session.query(db.func.sum(Sale.amount)).scalar() or 0
    today_sales = db.session.query(db.func.sum(Sale.amount)).filter(
        db.func.date(Sale.date) == today
    ).scalar() or 0
    monthly_sales = db.session.query(db.func.sum(Sale.amount)).filter(
        db.func.date(Sale.date) >= month_ago
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
                           monthly_sales=monthly_sales,
                           total_expenses=total_expenses,
                           monthly_expenses=monthly_expenses,
                           staff_performance=staff_performance,
                           now=datetime.now())


@app.route('/admin/staff')
@login_required
def manage_staff():
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('home'))

    staff_list = User.query.all()
    return render_template('admin/staff.html', staff_list=staff_list, now=datetime.now())


@app.route('/my-sales', methods=['GET', 'POST'])
@login_required
def my_sales():
    form = SalesQueryForm()
    end_date = datetime.today().date()
    date_num = end_date.strftime("%d")
    start_date = end_date - timedelta(days=int(date_num)-1)

    if form.validate_on_submit():
        start_date = form.start_date.data
        end_date = form.end_date.data

    # Query only current user's sales in date range
    sales = Sale.query.filter(
        Sale.staff_id == current_user.id,
        Sale.date >= start_date,
        Sale.date <= end_date
    ).order_by(Sale.date.desc()).all()

    # Calculate total
    total_sales = sum(sale.amount for sale in sales)

    return render_template('staff/my_sales.html',
                           sales=sales,
                           total_sales=total_sales,
                           form=form,
                           start_date=start_date,
                           end_date=end_date,
                           now=datetime.now())


@app.route('/export-my-sales')
@login_required
def export_my_sales():
    # Get the same date filters from request args
    try:
        start_date = datetime.strptime(request.args.get('start'), '%Y-%m-%d')
        end_date = datetime.strptime(request.args.get('end'), '%Y-%m-%d')
    except (TypeError, ValueError):
        # Default to last 30 days if no dates provided
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30)

    # Query the sales data (same as my_sales route)
    sales = Sale.query.filter(
        Sale.staff_id == current_user.id,
        Sale.date >= start_date,
        Sale.date <= end_date
    ).order_by(Sale.date.desc()).all()

    # Create CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow([
        'Date',
        'Amount',
        'Service Category',
        'Notes'
    ])

    # Write data rows
    for sale in sales:
        writer.writerow([
            sale.date.strftime('%Y-%m-%d'),
            sale.amount,
            sale.category,
            sale.notes or ''
        ])

    # Prepare response
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = (
        f"attachment; filename=my_sales_"
        f"{start_date.date()}_to_{end_date.date()}.csv"
    )
    response.headers["Content-type"] = "text/csv"
    return response


@app.route('/admin/reports', methods=['GET', 'POST'])
@login_required
def generate_reports():
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('home'))

    # Default report - last 30 days sales by category
    todays_date = datetime.today().date()
    date_num = todays_date.strftime("%d")
    start_date = todays_date - timedelta(days=int(date_num)-1)
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
                                   end_date=end_date,
                                   now=datetime.now()
                                   )

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
                                   end_date=end_date,
                                   now=datetime.now())

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
                                   end_date=end_date,
                                   now=datetime.now())

    return render_template('admin/reports.html',
                           start_date=start_date,
                           end_date=end_date,
                           now=datetime.now()
                           )


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


@app.route('/admin/edit-sale/<int:sale_id>', methods=['GET', 'POST'])
@login_required
def edit_sale(sale_id):
    if current_user.id > 3:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('home'))

    sale = Sale.query.get_or_404(sale_id)
    form = EditSaleForm(obj=sale)  # Pre-populate form with sale data

    if form.validate_on_submit():
        try:
            form.populate_obj(sale)  # Update sale with form data
            db.session.commit()
            flash('Sale updated successfully!', 'success')
            return redirect(url_for('staff_sales_report'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating sale: {str(e)}', 'danger')

    return render_template('admin/edit_sale.html', form=form, sale=sale, now=datetime.now())


@app.route('/admin/delete-sale/<int:sale_id>', methods=['POST'])
@login_required
def delete_sale(sale_id):
    if current_user.id > 3:
        return jsonify({'error': 'Unauthorized'}), 403

    sale = Sale.query.get_or_404(sale_id)
    db.session.delete(sale)
    db.session.commit()
    flash('Sale deleted successfully', 'success')
    return redirect(url_for('staff_sales_report'), now=datetime.now())


@app.route('/admin/staff/<int:staff_id>')
@login_required
def view_staff(staff_id):
    if not current_user.is_admin:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('home'))

    staff = User.query.get_or_404(staff_id)
    return render_template('admin/view_staff.html', staff=staff, now=datetime.now())


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

    return render_template('admin/edit_staff.html', staff=staff, now=datetime.now())


@app.route('/admin/reports/staff-sales', methods=['GET', 'POST'])
@login_required
def staff_sales_report():
    if current_user.id > 3:
        flash('Only admins can view this report', 'danger')
        return redirect(url_for('my_sales'))


    # Default to last 30 days
    end_date = datetime.today().date()
    date_num = end_date.strftime("%d")
    start_date = end_date - timedelta(days=int(date_num)-1)

    # Dates for edit/delete
    edit_end_date = end_date - timedelta(days=3)


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
        Sale.customer_name,
        Sale.id
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
                           start_date=start_date,
                           end_date=end_date,
                           selected_staff=request.form.get('staff_id', 'all'),
                           edit_end_date=edit_end_date,
                           now=datetime.now())


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
        r.Date.strftime('%Y-%m-%d'),
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
        date_format = workbook.add_format({'num_format': '%Y-%m-%d'})
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


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
