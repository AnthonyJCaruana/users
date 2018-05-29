# users
A high level library and REST API for user management using REDIS as the storage engine released under the GPLv3 licence

This library and service was originally writen for a project I am working on in my spare time to provide a web site for managing various 
software settings on an IOT device running on an ARM v7 proccesor with Ubuntu Linux as the underlying operating system. 

I only wanted authorised users to have access to the settings so I needed a way of allowing them to login to the system in a secure manner 
and manage other users as well as reset passwords and change email addresses.

I did not want to re-invent the wheel when it came to storage and I had the option of using either SqlLite or Redis for the data storage 
and went with Redis due to its rich types, linux support, and speed and the  ability to set a Time to Live (TTL) on the data.