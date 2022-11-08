# Generated by Django 4.1 on 2022-10-28 09:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('userinterface', '0016_downloadablefile_order_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='project',
            name='publicOverviewPassword',
            field=models.CharField(blank=True, default='', help_text='If no password is set, the public overview page is not accessible', max_length=64, null=True),
        ),
    ]