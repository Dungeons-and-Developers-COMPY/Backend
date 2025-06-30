# Backend


For your first time running the files do the following


In windows powershell enter 
```Python
$env:FLASK_APP = "__main__.py"
```

```Python
python __main__.py db init
python __main__.py db migrate -m "Initial migration"
python __main__.py db upgrade
```

To run:

```Python
python -m my_app
```