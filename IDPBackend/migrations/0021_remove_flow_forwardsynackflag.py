# Generated by Django 5.0 on 2024-03-26 19:09

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('IDPBackend', '0020_remove_flow_backwardsynflag'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='flow',
            name='ForwardSynAckFlag',
        ),
    ]
