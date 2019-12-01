
Django Ariadne JWT
==================

Support for JWT based authentication for use with the ariadne_ graphql library
running inside a Django_ project. It is heavily inspired by django-graph-jwt_.

Installation
------------
::

  pip install django-ariadne-jwt

How to use
----------

``django-ariadne-jwt`` aims to be easy to install and use.

First add ``JSONWebTokenBackend`` to your *AUTHENTICATION_BACKENDS*

.. code:: python

    AUTHENTICATION_BACKENDS = [
      "django_ariadne_jwt.backends.JSONWebTokenBackend",
      # Any other authentication backends...
      "django.contrib.auth.backends.ModelBackend",
    ]

Then add ``JSONWebTokenMiddleware`` to your view

.. code:: python

    from django_ariadne_jwt.middleware import JSONWebTokenMiddleware

    urlpatterns = [
      # Your other paths...
      path(
          "graphql/",
          csrf_exempt(
              GraphQLView.as_view(
                  schema=schema, middleware=[JSONWebTokenMiddleware()]
              )
          ),
          name="graphql"
      )
    ]


Or to your queries:

.. code:: python

    ariadne.graphql_sync(
        schema,
        {
            "query": """
            query {
                test
            }
            """
        },
        middleware=[JSONWebTokenMiddleware()],
    )


And then add the ``login_decorator`` to your resolvers before adding the field:

.. code:: python

    from django_ariadne_jwt.decorators import login_required

    @query_type.field("test")
    @login_required
    def resolve_test(*args):
      ...


This will prevent the field from resolving and ``ariadne`` will add an error to
the query result.

Finally add the type definitions and resolvers to the executable schema

.. code:: python

    from django_ariadne_jwt.resolvers import (
      auth_token_definition,
      auth_token_verification_definition,
      resolve_token_auth,
      resolve_refresh_token,
      resolve_verify_token,
    )

    type_definitions = """
      ...

      type Mutation {
        ...
        tokenAuth(username: String!, password: String!): AuthToken!
        refreshToken(token: String!): AuthToken!
        verifyToken(token: String!): AuthTokenVerification!
        ...
      }
    """

    auth_type_definitions = [
      auth_token_definition,
      auth_token_verification_definition,
    ]

    resolvers = [
      ...
    ]

    auth_resolvers = [
      resolve_token_auth,
      resolve_refresh_token,
      resolve_verify_token,
    ]

    schema = ariadne.make_executable_schema(
      [type_definitions] + auth_type_definitions, resolvers + auth_resolvers
    )

Once you get an auth token, set the HTTP Authorization header to:

``Token <token>``


How to contribute
-----------------

``django-ariadne-jwt`` is at a very early stage. It is currently
missing documentation, better testing and a lot of configuration options. Pull
requests with any of these are greatly appreciated.



``django-ariadne-jwt`` is missing feature X
-------------------------------------------

Feel free to open an issue or create a pull request with the implementation

.. _ariadne: https://ariadnegraphql.org/
.. _Django: https://www.djangoproject.com/
.. _django-graph-jwt: https://github.com/flavors/django-graphql-jwt>
.. _Python: http://python.org
