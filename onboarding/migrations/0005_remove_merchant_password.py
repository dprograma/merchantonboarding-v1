# Generated by Django 4.2.5 on 2023-10-16 15:15

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('onboarding', '0004_merchant_password'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='merchant',
            name='password',
        ),
    ]
