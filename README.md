[![CI Build](https://github.com/morulay/shiro-aad/workflows/CI%20Build/badge.svg)](https://github.com/morulay/shiro-aad/actions?query=workflow%3A%22CI+Build%22)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=morulay_shiro-aad&metric=alert_status)](https://sonarcloud.io/dashboard?id=morulay_shiro-aad)
[![Apache 2 License](https://img.shields.io/badge/license-Apache%202-blue.svg)](https://github.com/morulay/shiro-aad/blob/master/LICENSE)

# shiro-aad

Light integration of Apache Shiro with Microsoft Azure Active Directory based on [Microsoft identity platform ID tokens](https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens) and inspired by Microsoft's example of [a Java Web application that signs in users with the Microsoft identity platform and calls Microsoft Graph](https://github.com/Azure-Samples/ms-identity-java-webapp/tree/master/msal-java-webapp-sample) and [Azure Spring Boot](https://github.com/microsoft/azure-spring-boot) starter.

[Apache Shiro](https://shiro.apache.org) is a powerful and easy-to-use Java security framework with first class integration with [Spring Boot](https://shiro.apache.org/spring-boot.html). It comes with rich set of [Authentication](https://shiro.apache.org/authentication-features.html) and [Authorization](https://shiro.apache.org/authorization-features.html) features, including easy configuration, extendability and plugable data sources.

Compared to Spring Security Apache Shiro has one major difference, the default access control model. Spring Security authorization is build around users having one or many roles, where Apache Shiro has users having one or more roles and every role represents a set of permissions.

The advantage of Apache Shiro model is that there is no need to think about the roles upfront. During the development the [permissions](https://shiro.apache.org/permissions.html) are hard-coded marking the restricted arias in the code. At the end business decide how to group the permissions in roles and what role to give to every user.

The downside of Apache Shiro is the lack of built in support for OAuth2 or OpenID Connect and ready integration with well known providers like Apple, Github, GitLab, Google, Microsoft, Amazon, etc.

The goal of shiro-aad library is to provide such an integration with Microsoft Azure Active Directory for authentication purpose, i.e. user is authenticated with Azure Active Directory using OpenID Connect.

## Getting Started

In order to start with shiro-aad you have to add the following dependencies to your Maven project:

```xml
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-spring-boot-web-starter</artifactId>
    <version>1.5.3</version>
</dependency>
<dependency>
    <groupId>com.github.morulay</groupId>
    <artifactId>shiro-aad</artifactId>
    <version>0.2.0</version>
</dependency>
```

Afterwards you need to add to the `application.yml` or `application.properties` the mandatory properties corresponding to your personal or organization Azure Active Directory configuration:

```yml
shiro.aad:
  tenant: <tenant name>
  tenant-id: <tenant id>
  client-id: <client id>
```

The final step to have all working is to ensure you have Shiro realm configured, because shiro-aad covers only the authentication part of your application security and you have to take care for authorization.

The most easy approach is to have [JdbcRealm](https://shiro.apache.org/static/1.5.3/apidocs/org/apache/shiro/realm/jdbc/JdbcRealm.html) to handle the authorization. For example if you have the following DB schema:

![Sample Security Model](data:image/png;base64,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)

Then you need to add the following factory method in your application Java configuration:

```java
  @Bean
  public Realm realm(DataSource dataSource) {
    JdbcRealm realm = new JdbcRealm();
    realm.setDataSource(dataSource);
    realm.setUserRolesQuery(
        "select r.name from user u join role r on u.role_id = r.role_id where u.email = ? ");
    realm.setPermissionsQuery(
        "select p.permission from permission p join role r on r.role_id = p.role_id where r.name = ? ");
    realm.setPermissionsLookupEnabled(true);
    return realm;
  }
```

That's all. Now your application have Apache Shiro configured to make authentication against the Azure Active Directory and authorization against the application specific permissions and roles.

## Configuration Properties

shiro-aad supports the following properties specified inside your `application.properties` file, inside your `application.yml` file, or as command line switches:

| Key                           | Default Value                       | Description                                                                                                                                                                          |
| ----------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `shiro.aad.enabled`           | `true`                              | Whether to enable Azure AD integration                                                                                                                                               |
| `shiro.aad.tenant`            |                                     | Name of the tenant                                                                                                                                                                   |
| `shiro.aad.tenant-id`         |                                     | Tenant ID of the tenant                                                                                                                                                              |
| `shiro.aad.authority`         | `https://login.microsoftonline.com` | Microsoft authority instance base URL                                                                                                                                                |
| `shiro.aad.client-id`         |                                     | Unique application (client) ID assigned to your application by Azure AD when the application was registered                                                                          |
| `shiro.aad.redirect-uri`      | `/`                                 | URI where the identity provider will send the security tokens back to                                                                                                                |
| `shiro.aad.post-logout-uri`   |                                     | URI that the user is redirected to after successfully signing out. If not provided, the user is shown a generic message that's generated by the Microsoft identity platform endpoint |
| `shiro.aad.realm-name`        | `Azure Active Directory`            | Name of authorization realm                                                                                                                                                          |
| `shiro.aad.no-redirect-mimes` | `application/json`                  | Set of MIME types for which the filter will return `401 Unauthorized` instead to redirect using `302 Found` to authorization endpoint of Azure Active Directory                      |

## Additional Customizations

In addition to configuration properties shiro-aad allows the following customization:

### Customize what `Subject.getPrincipal()` method returns

By default the logged-in principal is represented by a `java.lang.String` holding the user's email. You can chang this by providing a Spring Bean that implements `com.github.morulay.shiro.aad.PrincipalFactory`

### Customize the default filter chanin definition

By default shiro-aad configures 2 filters:

- `authcOpenId` - requires OpenID Connect token or redirects to Azure Active Directory to obtain one
- `logout` - logouts the user from the application and from Azure Active Directory

and the following `org.apache.shiro.spring.web.config.ShiroFilterChainDefinition`:

```java
    if (aadProperties.getPostLogoutUri() != null) {
      chainDefinition.addPathDefinition(aadProperties.getPostLogoutUri(), "anon");
    }

    chainDefinition.addPathDefinition("/logout", "logout");
    chainDefinition.addPathDefinition("/**", "authcOpenId");
```

You can change this by providing Spring Bean of type `org.apache.shiro.spring.web.config.ShiroFilterChainDefinition`. It will override the default one and you can use the already configured `authcOpenId` and `logout` filters to make your own filter chain definition.
