# Generated by Django 4.1 on 2022-10-26 13:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('userinterface', '0012_downloadablefile_date_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='project',
            name='publicOverviewPassword',
            field=models.CharField(default='', help_text='If no password is set, the public overview page is not accessible', max_length=64),
        ),
    ]
