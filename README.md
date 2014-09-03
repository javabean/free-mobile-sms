Free-mobile-SMS
===============

This project exposes the Free Mobile SMS gateway as a web interface.

Requirements
------------
* a [Free Mobile](http://mobile.free.fr) subscription
* Java 7
* Tomcat 7
* Maven 3 for compiling

Compiling
---------

	mvn -Dmaven.test.skip clean package -Duser=12345678 -Dpass=aB1dE2gH3iJklM

and then deploy the resulting `.war` file in a Servlet container (e.g. Tomcat).