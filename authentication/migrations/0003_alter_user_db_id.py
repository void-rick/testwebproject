# Generated by Django 4.2 on 2023-05-04 12:07

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0002_passwordlocklogin'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user_db',
            name='id',
            field=models.PositiveIntegerField(primary_key=True, serialize=False, validators=[django.core.validators.MinValueValidator(0)]),
        ),
    ]
