# Generated by Django 5.0 on 2024-01-29 22:51

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('IDPBackend', '0004_flow_seqnumber'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='flow',
            name='seqNumber',
        ),
    ]
