****
# Math Quizzes Project Description

## Goal
### _To create an educational web app for kindergarten through 12th grade students that allows their teachers to assign them math problems._

----


## Overview
* Each problem in the app's database will be tagged with both **keywords** and a **difficulty level** (Low, Medium, and High).
  * The instructor interface needs the ability to specify a number of problems a student should need to complete at each difficulty level in order to advance to the next level.
    * If an instructor decides that each student will answer, for example, 6 problems at the **Low** difficulty level
    * The web app will only allow a student to advance to the **Medium** difficulty level after correctly answering 6  **Low** level problems. 

* Instructors need a summary to view all students:
  * Results 
  * Results at each Difficulty level
  * Include a link to the actual problems

* _The client will provide the problems, tagged with the standard, difficulty level, and keyword(s)._

----


### Client Info
Clara Valtorta

[cgvaltorta@gmail.com]()

[Website](https://www.linkedin.com/in/clara-valtorta-2b579a1b)

----


### Platforms
* Windows
* Mac
* Tablets

----


# Technical Requirements

**Products:** [App Engine][1]

**Language:** [Python][2]

**APIs**
- [NDB Datastore API][3]
- [Users API][4]

**Dependencies**
- [webapp2][5]
- [jinja2][6]
- [Twitter Bootstrap][7]

[1]: https://developers.google.com/appengine
[2]: https://python.org
[3]: https://developers.google.com/appengine/docs/python/ndb/
[4]: https://developers.google.com/appengine/docs/python/users/
[5]: http://webapp-improved.appspot.com/
[6]: http://jinja.pocoo.org/docs/
[7]: http://twitter.github.com/bootstrap/

----


# Run Info

### To run locally:

     dev_appserver.py ./
     
### To deploy:

     gcloud app deploy ./app.yaml ./index.yaml

### To update a modified data store index:

     gcloud preview datastore cleanup-indexes ./index.yaml
     gcloud preview datastore create-indexes ./index.yaml
     gcloud app deploy ./index.yaml ./app.yaml
