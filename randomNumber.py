
# generate random integer values
from random import seed
from random import randint
# seed random number generator
seed(4359483843435)


seed(seed)
# generate some integers
for _ in range(1):
    value = randint(333, 1300)
    print(value)
