FROM golang:1.16 as base

# Set Timezone
RUN echo "Europe/Berlin" > /etc/timezone
RUN ln -snf /usr/share/zoneinfo/Europe/Berlin /etc/localtime

# Copy Source
COPY . /srv/backend
RUN rm -rf /srv/backend/.git*
WORKDIR /srv/backend
RUN ls -la

# Compile
RUN make

# Set Environment & Service
ARG environment
ENV environment "${environment}"
ARG service
ENV service "${service}"

# Entrypoint
ENTRYPOINT [ "/srv/backend/entrypoint.sh" ]

# Ports
EXPOSE 8888
EXPOSE 9999
