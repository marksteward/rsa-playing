FROM ubuntu

RUN apt update && apt -y install libssl-dev python3 python3-pip
RUN pip3 install libnum

RUN mkdir /app
WORKDIR /app

COPY genprimes.py ./

CMD python3 genprimes.py

