# Generated by Django 4.2.5 on 2023-12-18 14:36

import datetime
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('onboarding', '0012_merchant_phone_number'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='merchant',
            options={},
        ),
        migrations.RemoveField(
            model_name='merchant',
            name='other_names',
        ),
        migrations.AddField(
            model_name='merchant',
            name='account_number',
            field=models.CharField(blank=True, max_length=20, null=True, verbose_name='Account Number'),
        ),
        migrations.AddField(
            model_name='merchant',
            name='avatar',
            field=models.ImageField(blank=True, default='profile/avatar.png', null=True, upload_to='profile/'),
        ),
        migrations.AddField(
            model_name='merchant',
            name='bank_name',
            field=models.CharField(blank=True, choices=[('bank1', 'Bank 1'), ('bank2', 'Bank 2'), ('bank3', 'Bank 3')], max_length=255, null=True, verbose_name='Bank Name'),
        ),
        migrations.AddField(
            model_name='merchant',
            name='business_certificate',
            field=models.FileField(blank=True, help_text='Upload the business name certificate', null=True, upload_to='business/certificates/', verbose_name='Business Certificate'),
        ),
        migrations.AddField(
            model_name='merchant',
            name='business_name',
            field=models.CharField(blank=True, max_length=255, null=True, verbose_name='Business Name'),
        ),
        migrations.AddField(
            model_name='merchant',
            name='bvn',
            field=models.CharField(blank=True, max_length=11, null=True, verbose_name='BVN'),
        ),
        migrations.AddField(
            model_name='merchant',
            name='enter_bvn_number',
            field=models.CharField(blank=True, max_length=11, null=True, verbose_name='Enter BVN Number'),
        ),
        migrations.AddField(
            model_name='merchant',
            name='id_type',
            field=models.CharField(blank=True, max_length=50, null=True, verbose_name='ID Type'),
        ),
        migrations.AddField(
            model_name='merchant',
            name='is_locked',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='merchant',
            name='last_login_ip',
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='merchant',
            name='last_login_user_agent',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='merchant',
            name='profile_picture',
            field=models.ImageField(blank=True, help_text='Upload a profile picture with a maximum size of 500x500 pixels', null=True, upload_to='business/profile_pictures/', verbose_name='Profile Picture'),
        ),
        migrations.AddField(
            model_name='merchant',
            name='rc_certificate',
            field=models.FileField(blank=True, help_text='Upload the RC number certificate', null=True, upload_to='business/rc_certificates/', verbose_name='RC Certificate'),
        ),
        migrations.AddField(
            model_name='merchant',
            name='rc_number',
            field=models.CharField(blank=True, max_length=50, null=True, verbose_name='RC Number'),
        ),
        migrations.AddField(
            model_name='merchant',
            name='tax_certificate',
            field=models.FileField(blank=True, help_text='Upload the Tax ID certificate', null=True, upload_to='business/tax_certificates/', verbose_name='Tax Certificate'),
        ),
        migrations.AddField(
            model_name='merchant',
            name='tax_id',
            field=models.CharField(blank=True, max_length=50, null=True, verbose_name='Tax ID'),
        ),
        migrations.AddField(
            model_name='merchant',
            name='upload_id',
            field=models.FileField(blank=True, null=True, upload_to='verification/upload_ids/', verbose_name='Upload ID'),
        ),
        migrations.AlterField(
            model_name='merchant',
            name='email',
            field=models.EmailField(blank=True, max_length=254, null=True, unique=True),
        ),
        migrations.AlterField(
            model_name='merchant',
            name='last_name',
            field=models.CharField(blank=True, max_length=100),
        ),
        migrations.AlterField(
            model_name='merchant',
            name='password',
            field=models.CharField(max_length=128, verbose_name='password'),
        ),
        migrations.AlterField(
            model_name='merchant',
            name='phone_number',
            field=models.CharField(blank=True, max_length=15, null=True, unique=True),
        ),
        migrations.CreateModel(
            name='OTPVerification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('phone_otp', models.CharField(blank=True, max_length=6, null=True)),
                ('email_otp', models.CharField(blank=True, max_length=6, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('attempts', models.IntegerField(default=0)),
                ('merchant', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='otp', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='LoginAttempt',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.CharField(max_length=45, unique=True)),
                ('attempts', models.PositiveIntegerField(default=0)),
                ('last_attempt_time', models.DateTimeField(auto_now=True, null=True)),
                ('lockout_duration', models.DurationField(default=datetime.timedelta(seconds=900))),
                ('max_login_attempts', models.PositiveIntegerField(default=3)),
                ('merchant', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='login_attempts', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
