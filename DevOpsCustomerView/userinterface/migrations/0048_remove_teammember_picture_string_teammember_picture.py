# Generated by Django 4.2.16 on 2024-10-14 08:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('userinterface', '0047_teammember_code_teammember_description_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='teammember',
            name='picture_string',
        ),
        migrations.AddField(
            model_name='teammember',
            name='picture',
            field=models.ImageField(blank=True, upload_to='team_pictures/'),
        ),
    ]