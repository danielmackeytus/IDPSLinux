# Generated by Django 5.0 on 2024-02-04 18:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('IDPBackend', '0005_remove_flow_seqnumber'),
    ]

    operations = [
        migrations.AddField(
            model_name='flow',
            name='authFailures',
            field=models.CharField(default=0, max_length=5),
            preserve_default=False,
        ),
    ]
