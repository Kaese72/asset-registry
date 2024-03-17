# Asset registry

## Database setup

Requires mariadb. Once there is one, create the database

```
CREATE DATABASE assetregistry;
```

Then grant priveleges on that database to a user

```
GRANT ALL PRIVILEGES ON assetregistry.* to '<USERNAME>'@'%' IDENTIFIED BY '<PASSWORD>';
```