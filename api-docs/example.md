# Title

---

<_Additional information about your API call. Try to use verbs that match both request type (fetching vs modifying) and plurality (one vs multiple)._>

## URL

<_The URL Structure (path only, no root url)_>

## Method:

<_The request type_>

`GET` | `POST` | `DELETE` | `PUT`

* **URL Params**

  <_If URL params exist, specify them in accordance with name mentioned in URL section. Separate into optional and required. Document data constraints._>

  **Required:**

  `id=[integer]`

  **Optional:**

  `photo_id=[alphanumeric]`

## Data Params

<_If making a post request, what should the body payload look like? URL Params rules apply here too._>

## Success Response:

<_What should the status code be on success and is there any returned data? This is useful when people need to to know what their callbacks should expect!_>

### Code

200

#Content

```
{ id : 12 }
```

## Error Responses:

<_Most endpoints will have many ways they can fail. From unauthorized access, to wrongful parameters etc. All of those should be liste d here. It might seem repetitive, but it helps prevent assumptions from being made where they should be._>

### Code

`401 UNAUTHORIZED`

### Content

```
{ error : "Log in" }
```

### Code

```
422 UNPROCESSABLE ENTRY
```

### Content

```
{ error : "Email Invalid" }
```

## Sample Call:

<_Just a sample call to your endpoint in a runnable format ($.ajax call or a curl request) - this makes life easier and more predictable._>

## Notes:

<_This is where all uncertainties, commentary, discussion etc. can go. I recommend timestamping and identifying oneself when leaving comments here._>
