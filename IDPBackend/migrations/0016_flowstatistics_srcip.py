# Generated by Django 5.0 on 2024-02-19 22:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('IDPBackend', '0015_flow_origin'),
    ]

    operations = [
        migrations.AddField(
            model_name='flowstatistics',
            name='srcIP',
            field=models.JSONField(default=0),
            preserve_default=False,
        ),
    ]
