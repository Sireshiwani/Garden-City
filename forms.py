from flask_wtf import FlaskForm
from wtforms import DateField, SubmitField
from wtforms.validators import DataRequired, ValidationError
from datetime import datetime

class SalesQueryForm(FlaskForm):
    start_date = DateField('Start Date', validators=[DataRequired()])
    end_date = DateField('End Date', validators=[DataRequired()])
    submit = SubmitField('Filter')


    def validate_end_date(self, field):
        if self.start_date.data and field.data:
            if field.data < self.start_date.data:
                raise ValidationError("End date must be after start date")
            if field.data > datetime.utcnow().date():
                raise ValidationError("Future dates not allowed")

        def validate_end_date(self, field):
            if self.start_date.data and field.data:
                if field.data < self.start_date.data:
                    raise ValidationError("End date must be after start date")
                if field.data > datetime.utcnow().date():
                    raise ValidationError("Future dates not allowed")