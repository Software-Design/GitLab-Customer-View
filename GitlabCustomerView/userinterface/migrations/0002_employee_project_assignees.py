# Generated by Django 4.1 on 2022-08-05 07:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('userinterface', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Employee',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=200)),
                ('email', models.CharField(max_length=200)),
                ('phone', models.CharField(max_length=200)),
                ('gitlabUsername', models.CharField(max_length=200)),
            ],
        ),
        migrations.AddField(
            model_name='project',
            name='assignees',
            field=models.ManyToManyField(to='userinterface.employee'),
        ),
    ]
