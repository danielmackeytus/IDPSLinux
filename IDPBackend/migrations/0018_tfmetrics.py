# Generated by Django 5.0 on 2024-03-13 21:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('IDPBackend', '0017_remove_appuser_username_alter_appuser_is_superuser'),
    ]

    operations = [
        migrations.CreateModel(
            name='TFMetrics',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('accuracy', models.CharField(max_length=35)),
                ('loss', models.CharField(max_length=35)),
                ('val_accuracy', models.CharField(max_length=35)),
                ('val_loss', models.CharField(max_length=35)),
            ],
        ),
    ]
