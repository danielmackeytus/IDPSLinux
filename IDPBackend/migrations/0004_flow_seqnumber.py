# Generated by Django 5.0 on 2024-01-29 22:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('IDPBackend', '0003_flow_fwduniqueports'),
    ]

    operations = [
        migrations.AddField(
            model_name='flow',
            name='seqNumber',
            field=models.CharField(default=0, max_length=10),
            preserve_default=False,
        ),
    ]
