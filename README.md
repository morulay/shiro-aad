# shiro-azure

Light integration of Apache Shiro with Microsoft Azure Active Direcory based on [Microsoft identity platfoprm ID tokens](https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens) and inspired by Microsoft's example of [a Java Web application that signs in users with the Microsoft identity platform and calls Microsoft Graph](https://github.com/Azure-Samples/ms-identity-java-webapp/tree/master/msal-java-webapp-sample) and [Azure Spring Boot](https://github.com/microsoft/azure-spring-boot) starter.

[Apache Shiro](https://shiro.apache.org) is a powerful and easy-to-use Java security framework with very good intrgation with Spring Boot. It comes with rich set of [Authentication](https://shiro.apache.org/authentication-features.html) and [Authorization](https://shiro.apache.org/authorization-features.html) features, including easy configuration, extendability and pluggable data sources.

Compared to Spring Security Apache Shiro has one major difference, the default access control model. Spring Securuty authorization is build arround users having one or many roles, where Apache Shiro has users having one or more roles and every role represnts a set of permissions.

The advantage of Apache Shiro model is that there is no need to think about the roles upfront. During the development the permissions are hard-coded marking the restricted arias in the code. At the end business users decide how to group the permissions in roles and what role to give to every user.

The downside of Apache Shiro is the lack of buit in support for OAuth2 or OpenID Connect and ready integration with well known providers like Apple, Github, GitLab, Google, Microsoft, Amazone, etc.

The goal of shiro-aad library is to provide such an integration with Microsoft Azure Active Direcotry for authentication purpose, i.e. user is authenticated with Azure Active Directory using OpenID Connect.
