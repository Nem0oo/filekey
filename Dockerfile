FROM httpd:alpine3.21
ARG SHA
RUN echo $SHA > /usr/local/apache2/htdocs/version.txt
COPY . /usr/local/apache2/htdocs/