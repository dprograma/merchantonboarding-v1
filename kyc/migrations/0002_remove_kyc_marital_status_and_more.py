# Generated by Django 4.2.5 on 2023-12-18 14:36

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('kyc', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='kyc',
            name='marital_status',
        ),
        migrations.RemoveField(
            model_name='kyc',
            name='permanent_address',
        ),
        migrations.RemoveField(
            model_name='kyc',
            name='place_of_birth',
        ),
        migrations.RemoveField(
            model_name='kyc',
            name='proof_of_income',
        ),
    ]
