# Generated by Django 5.0 on 2024-03-28 04:04

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('IDPBackend', '0021_remove_flow_forwardsynackflag'),
    ]

    operations = [
        migrations.RenameField(
            model_name='flow',
            old_name='flowID',
            new_name='forward',
        ),
    ]
