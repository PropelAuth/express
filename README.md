<p align="center">
  <a href="https://www.propelauth.com?ref=github" target="_blank" align="center">
    <img src="https://www.propelauth.com/imgs/lockup.svg" width="200">
  </a>
</p>

# PropelAuth Express Library

An Express library for managing authentication, backed by [PropelAuth](https://www.propelauth.com?ref=github). 

[PropelAuth](https://www.propelauth.com?ref=github) makes it easy to add authentication and authorization to your B2B/multi-tenant application.

Your frontend gets a beautiful, safe, and customizable login screen. Your backend gets easy authorization with just a few lines of code. You get an easy-to-use dashboard to config and manage everything.

## Documentation

- Full reference this library is [here](https://docs.propelauth.com/reference/backend-apis/express)
- Getting started guides for PropelAuth are [here](https://docs.propelauth.com/)

## Installation

```shell
npm install @propelauth/express
```


## Initialize

`initAuth` performs a one-time initialization of the library.
It will verify your `apiKey` is correct and fetch the metadata needed to verify access tokens in [requireUser](#protect-api-routes) and optionalUser.

```typescript 
import { initAuth } from '@propelauth/express';

const {
    requireUser,
    fetchUserMetadataByUserId,
    // ...
} = initAuth({
    authUrl: "REPLACE_ME",
    apiKey: "REPLACE_ME",
});
```

## Protect API Routes

The `@propelauth/express` library provides an Express middleware `requireUser`.
This middleware will verify the access token and set `req.userClass` to the [User Class](https://docs.propelauth.com/reference/backend-apis/express#user-class) if it's valid.

```typescript
import { initAuth } from '@propelauth/express';

const { requireUser } = initAuth({ /* ... */ });

app.get("/api/whoami", requireUser, (req, res) => {
    res.text("Hello user with ID " + req.userClass.userId);
});
```

Otherwise, the request is rejected with a 401 Unauthorized.
You can also use `optionalUser` if you want the request to proceed in either case.

```typescript
import { initAuth } from '@propelauth/express';

const { optionalUser } = initAuth({ /* ... */ });

app.get("/api/whoami", optionalUser, (req, res) => {
    if (req.user) {
        res.text("Hello user with ID " + req.userClass.userId);
    } else {
        res.text("Hello unauthenticated user");
    }
});
```

## Authorization / Organizations

You can also verify which organizations the user is in, and which roles and permissions they have in each organization all through the [User](https://docs.propelauth.com/reference/backend-apis/express#user-class) or [OrgMemberInfo](https://docs.propelauth.com/reference/backend-apis/express#org-member-info) Classes.

### Check Org Membership

Verify that the request was made by a valid user **and** that the user is a member of the specified organization.

```js
app.get('/api/org/:orgId', requireUser, async (req, res) => {
    const org = req.userClass.getOrg(req.params.orgId)
    if (!org) {
        // return 403 error
    } else {
        res.json(`You are in org ${org.orgName}`)
    }
})
```

### Check Org Membership and Role

Similar to checking org membership, but will also verify that the user has a specific Role in the organization.

A user has a Role within an organization. By default, the available roles are Owner, Admin, or Member, but these can be configured. These roles are also hierarchical, so Owner > Admin > Member.

```js
app.get('/api/org/:orgId', requireUser, async (req, res) => {
    const org = req.userClass.getOrg(req.params.orgId)
    if (!org || !org.isRole('Owner')) {
        // return 403 error
    } else {
        res.json(`You are an Owner in org ${org.orgName}`)
    }
})
```

### Check Org Membership and Permission

Similar to checking org membership, but will also verify that the user has the specified permission in the organization.

Permissions are arbitrary strings associated with a role. For example, `can_view_billing`, `ProductA::CanCreate`, and `ReadOnly` are all valid permissions. You can create these permissions in the PropelAuth dashboard.

```js
app.get('/api/org/:orgId', requireUser, async (req, res) => {
    const org = req.userClass.getOrg(req.params.orgId)
    if (!org || !org.hasPermission('can_view_billing')) {
        // return 403 error
    } else {
        res.json(`You can view billing information for org ${org.orgName}`)
    }
})
```

## Calling Backend APIs

You can also use the library to call the PropelAuth APIs directly, allowing you to fetch users, create orgs, and a lot more.

```ts
const auth = initAuth({
    authUrl: 'REPLACE_ME',
    apiKey: 'REPLACE_ME',
})

const magicLink = await auth.createMagicLink({
    email: 'user@customer.com',
})
```

See the [API Reference](https://docs.propelauth.com/reference) for more information.

## Questions?

Feel free to reach out at support@propelauth.com

