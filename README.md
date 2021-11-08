[![Build & Analyze](https://github.com/morulay/shiro-aad/actions/workflows/sonar.yml/badge.svg)](https://github.com/morulay/shiro-aad/actions/workflows/sonar.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=morulay_shiro-aad&metric=alert_status)](https://sonarcloud.io/dashboard?id=morulay_shiro-aad)
[![Maven Central](https://img.shields.io/maven-central/v/com.github.morulay/shiro-aad)](https://mvnrepository.com/artifact/com.github.morulay/shiro-aad)
[![Apache 2 License](https://img.shields.io/badge/license-Apache%202-blue.svg)](https://github.com/morulay/shiro-aad/blob/master/LICENSE)

# shiro-aad

- [Getting Started](#getting-started)
- [Configuration Properties](#configuration-properties)
- [Additional Customizations](#additional-customizations)
  - [Customize what Subject.getPrincipal() method returns](#customize-what-subjectgetprincipal-method-returns)
  - [Customize the default filter chain definition](#customize-the-default-filter-chanin-definition)
- [Run As Support](#run-as-support)

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
    <version>1.7.1</version>
</dependency>
<dependency>
    <groupId>com.github.morulay</groupId>
    <artifactId>shiro-aad</artifactId>
    <version>1.1.0-SNAPSHOT</version>
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

![Sample Security Model](/images/sample-security-model.png))

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

| Key                           | Default Value                       | Description                                                                                                                                                                                          |
| ----------------------------- | ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `shiro.aad.enabled`           | `true`                              | Whether to enable Azure AD integration                                                                                                                                                               |
| `shiro.aad.tenant`            |                                     | Name of the tenant                                                                                                                                                                                   |
| `shiro.aad.tenant-id`         |                                     | Tenant ID of the tenant                                                                                                                                                                              |
| `shiro.aad.authority`         | `https://login.microsoftonline.com` | Microsoft authority instance base URL                                                                                                                                                                |
| `shiro.aad.client-id`         |                                     | Unique application (client) ID assigned to your application by Azure AD when the application was registered                                                                                          |
| `shiro.aad.redirect-uri`      | `/`                                 | URI where the identity provider will send the security tokens back to                                                                                                                                |
| `shiro.aad.post-logout-uri`   |                                     | URI that the user is redirected to after successfully signing out. If not provided, the user is shown a generic message that's generated by the Microsoft identity platform endpoint                 |
| `shiro.aad.realm-name`        | `Azure Active Directory`            | Name of authorization realm                                                                                                                                                                          |
| `shiro.aad.filter-chain-defs` |                                     | Path to filter definition(s) mapping, allowing customization of default filter chain definition. When using YAML be careful to escape forward slashes, e.g. `/static` should be `"[/static/**]"` |

## Additional Customizations

In addition to configuration properties shiro-aad allows the following customization:

### Customize what `Subject.getPrincipal()` method returns

By default the logged-in principal is represented by a `java.lang.String` holding the user's email. You can chang this by providing a Spring Bean that implements `com.github.morulay.shiro.aad.PrincipalFactory`

### Customize the default filter chanin definition

By default shiro-aad configures 2 filters:

- `authcOpenId` - requires OpenID Connect token or redirects to Azure Active Directory to obtain one
- `logout` - logouts the user from the application and from Azure Active Directory

and requires authentication for all resources (`/**`) except the path defined with `shiro.aad.post-logout-uri` property.

There are two options to customize this default behavior:

- using `shiro.aad.filter-chain-defs` property. For example:

```yaml
shiro:
  aad:
    filter-chain-defs:
      "[/static/**]": anon
```

- Or providing Spring Bean of type `org.apache.shiro.spring.web.config.ShiroFilterChainDefinition`. It will override default one and you can use the already configured `authcOpenId` and `logout` filters to make your own filter chain definition. For example:

```java
  @Bean
  public ShiroFilterChainDefinition shiroFilterChainDefinition() {
    DefaultShiroFilterChainDefinition chainDefinition = new DefaultShiroFilterChainDefinition();

    // Place your customization here
    chainDefinition.addPathDefinition("/static", "anon");

    // Don't forget to always include the following lines at the end
    if (aadProperties.getPostLogoutUri() != null) {
      chainDefinition.addPathDefinition(aadProperties.getPostLogoutUri(), "anon");
    }

    chainDefinition.addPathDefinition("/logout", "logout");
    chainDefinition.addPathDefinition("/**", "authcOpenId");
    return chainDefinition;
  }
```

## Run As Support

Apache Shiro supports “Run As”, a feature that allows users to assume the identity of another user (if they are allowed), sometimes referred as “Impersonation”

The default Apache Shiro “Run As” implementation relies on storing the principals stack in the session.

shiro-aad is totally stateless. It makes login and logout on every request relying on the OpenId token stored as a cookie to preserve the identity.

In a similar fashion the “Run As” identity is preserved in dedicated encrypted RunAs token stored as cookie. If there is RunAs token, the “Run As” identity is restored on every request, after a successful login. Any change of the “Run As” identity leads to update or removal of the RunAs token.
