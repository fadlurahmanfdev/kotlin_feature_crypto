# How To:

### How To Use In Your Project

Add below code in your setting gradle

```
dependencyResolutionManagement {
		repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
		repositories {
			mavenCentral()
			maven { url = uri("https://jitpack.io") }
		}
	}
```

Add below code in your gradle project (see latest-release in [releases](https://github.com/fadlurahmanfdev/core_crypto/releases))

```
implementation("com.github.fadlurahmanfdev:core_crypto:latest-release")
```
