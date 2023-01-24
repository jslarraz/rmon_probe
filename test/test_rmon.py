import pytest
import subprocess

## Sets

@pytest.fixture
def set_cmd():
    return ["snmpset", "-v", "2c", "-c", "private", "localhost"]

@pytest.fixture
def get_cmd():
    return ['snmpget', '-v', '2c', '-c', 'private', 'localhost']

@pytest.fixture
def walk_cmd():
    return ['snmpwalk', '-v', '2c', '-c', 'private', 'localhost']

@pytest.fixture
def idx():
    global n
    n += 1
    return n

n = 0

@pytest.fixture(autouse=True)
def assert_empty(get_cmd, set_cmd, walk_cmd, idx):
    output = subprocess.run(walk_cmd + ['1.3.6.1.2.1.16.7'], capture_output=True, check=False)
    assert output.stdout.decode() == 'iso.3.6.1.2.1.16.7 = No Such Object available on this agent at this OID\n'
    yield
    output = subprocess.run(walk_cmd + ['1.3.6.1.2.1.16.7'], capture_output=True, check=False)
    assert output.stdout.decode() == 'iso.3.6.1.2.1.16.7 = No Such Object available on this agent at this OID\n'





########## FUNCTIONAL TESTING
# From Non-existent to valid
def test_none_valid(set_cmd, walk_cmd, idx):
    output = subprocess.run(set_cmd + ['1.3.6.1.2.1.16.7.1.1.1.11.%d' % idx, 'i', '1'], check=False)
    output = subprocess.run(walk_cmd + ['1.3.6.1.2.1.16.7'], capture_output=True, check=False)
    assert output.stdout.decode() == 'iso.3.6.1.2.1.16.7 = No Such Object available on this agent at this OID\n'


# From Non-existent to underCreation with createRequest
def test_none_create(set_cmd, walk_cmd, idx):
    subprocess.run(set_cmd + ['1.3.6.1.2.1.16.7.1.1.1.11.%d' % idx, 'i', '2'], check=False)
    output = subprocess.run(walk_cmd + ['1.3.6.1.2.1.16.7'], capture_output=True, check=False)
    subprocess.run(set_cmd + ['1.3.6.1.2.1.16.7.1.1.1.11.%d' % idx, 'i', '4'], check=False)
    assert output.stdout.decode() == '''iso.3.6.1.2.1.16.7.1.1.1.1.%(idx)d = INTEGER: %(idx)d
iso.3.6.1.2.1.16.7.1.1.1.2.%(idx)d = INTEGER: 0
iso.3.6.1.2.1.16.7.1.1.1.3.%(idx)d = INTEGER: 0
iso.3.6.1.2.1.16.7.1.1.1.4.%(idx)d = ""
iso.3.6.1.2.1.16.7.1.1.1.5.%(idx)d = ""
iso.3.6.1.2.1.16.7.1.1.1.6.%(idx)d = ""
iso.3.6.1.2.1.16.7.1.1.1.7.%(idx)d = INTEGER: 0
iso.3.6.1.2.1.16.7.1.1.1.8.%(idx)d = INTEGER: 0
iso.3.6.1.2.1.16.7.1.1.1.9.%(idx)d = INTEGER: 0
iso.3.6.1.2.1.16.7.1.1.1.10.%(idx)d = ""
iso.3.6.1.2.1.16.7.1.1.1.11.%(idx)d = INTEGER: 3'''.strip() % {"idx": idx} + '\n'







########## TEST ERRORS



# https://www.rfc-editor.org/rfc/rfc1905#section-4.2.5 (2)
def test_not_table(set_cmd):
    output = subprocess.run(set_cmd + ['1.3.6.1.2.1.16.7.1.1.1.11.2.3', 'i', '1'], capture_output=True, check=False)
    assert output.stderr.decode() == '''Error in packet.
Reason: notWritable (That object does not support modification)
Failed object: iso.3.6.1.2.1.16.7.1.1.1.11.2.3\n\n'''

# https://www.rfc-editor.org/rfc/rfc1905#section-4.2.5 (3)
def test_wrongType(set_cmd):
    output = subprocess.run(set_cmd + ['1.3.6.1.2.1.16.7.1.1.1.1.60000', 's', 'asdf'], capture_output=True, check=False)
    assert output.stderr.decode() == '''Error in packet.
Reason: wrongType (The set datatype does not match the data type the agent expects)
Failed object: iso.3.6.1.2.1.16.7.1.1.1.1.60000\n\n'''

# https://www.rfc-editor.org/rfc/rfc1905#section-4.2.5 (4)
def test_wrongLength_max(set_cmd):
    output = subprocess.run(set_cmd + ['1.3.6.1.2.1.16.7.1.1.1.10.60000', 's', 'a'*128], capture_output=True, check=False)
    assert output.stderr.decode() == '''Error in packet.
Reason: wrongLength (The set value has an illegal length from what the agent expects)
Failed object: iso.3.6.1.2.1.16.7.1.1.1.10.60000\n\n'''

# https://www.rfc-editor.org/rfc/rfc1905#section-4.2.5 (6)
def test_wrongValue_min(set_cmd):
    output = subprocess.run(set_cmd + ['1.3.6.1.2.1.16.7.1.1.1.1.60000', 'i', '0'], capture_output=True, check=False)
    assert output.stderr.decode() == '''Error in packet.
Reason: wrongValue (The set value is illegal or unsupported in some way)
Failed object: iso.3.6.1.2.1.16.7.1.1.1.1.60000\n\n'''

# https://www.rfc-editor.org/rfc/rfc1905#section-4.2.5 (6)
def test_wrongValue_max(set_cmd):
    output = subprocess.run(set_cmd + ['1.3.6.1.2.1.16.7.1.1.1.1.60000', 'i', '70000'], capture_output=True, check=False)
    assert output.stderr.decode() == '''Error in packet.
Reason: wrongValue (The set value is illegal or unsupported in some way)
Failed object: iso.3.6.1.2.1.16.7.1.1.1.1.60000\n\n'''


# https://www.rfc-editor.org/rfc/rfc1905#section-4.2.5 (8)
def test_inconsistentName(set_cmd):
    output = subprocess.run(set_cmd + ['1.3.6.1.2.1.16.7.1.1.1.1.60000', 'i', '60000'], capture_output=True, check=False)
    assert output.stderr.decode() == '''Error in packet.
Reason: inconsistentName (That object can not currently be created)
Failed object: iso.3.6.1.2.1.16.7.1.1.1.1.60000\n\n'''




# https://www.rfc-editor.org/rfc/rfc1905#section-4.2.5 (9)
def test_notWritable(set_cmd, idx):
    errors = []
    # Create entry
    output = subprocess.run(set_cmd + ['1.3.6.1.2.1.16.7.1.1.1.11.%d' % idx, 'i', '2'], capture_output=True, check=False)
    if output.stdout.decode() != '''iso.3.6.1.2.1.16.7.1.1.1.11.%d = INTEGER: 2\n''' % idx:
        errors.append("Error while creating entry with index = %d. " % idx + output.stdout.decode())

    # Pass entry to valid
    output = subprocess.run(set_cmd + ['1.3.6.1.2.1.16.7.1.1.1.11.%d' % idx, 'i', '1'], capture_output=True, check=False)
    if output.stdout.decode() != '''iso.3.6.1.2.1.16.7.1.1.1.11.%d = INTEGER: 1\n''' % idx:
        errors.append("Error while passing entry with index = %d to valid. " % idx + output.stdout.decode())

    # Write a valid value to the previously created entry
    output = subprocess.run(set_cmd + ['1.3.6.1.2.1.16.7.1.1.1.10.%d' % idx, 's', 'Jorge'], capture_output=True, check=False)
    if output.stderr.decode() != '''Error in packet.
Reason: notWritable (That object does not support modification)
Failed object: iso.3.6.1.2.1.16.7.1.1.1.10.%d\n\n''' % idx:
        errors.append("Unexpected response while modifying the owner entry. " + output.stderr.decode())

    # Clean
    subprocess.run(set_cmd + ['1.3.6.1.2.1.16.7.1.1.1.11.%d' % idx, 'i', '4'], check=False)
    assert len(errors) == 0




# https://www.rfc-editor.org/rfc/rfc1905#section-4.2.5 (9)
def test_notWritable2(set_cmd, idx):
    errors = []
    # Create entry
    output = subprocess.run(set_cmd + ['1.3.6.1.2.1.16.7.1.1.1.11.%d' % idx, 'i', '2'], capture_output=True, check=False)
    if output.stdout.decode() != '''iso.3.6.1.2.1.16.7.1.1.1.11.%d = INTEGER: 2\n''' % idx:
        errors.append("Error while creating entry with index = %d. " % idx + output.stdout.decode())

    # Write a valid value to the previously created entry
    output = subprocess.run(set_cmd + ['1.3.6.1.2.1.16.7.1.1.1.1.%d' % idx, 'i', '1'], capture_output=True, check=False)
    if output.stderr.decode() != '''Error in packet.
Reason: notWritable (That object does not support modification)
Failed object: iso.3.6.1.2.1.16.7.1.1.1.1.%d\n\n''' % idx:
        errors.append("Unexpected response while modifying the owner entry. " + output.stderr.decode())

    subprocess.run(set_cmd + ['1.3.6.1.2.1.16.7.1.1.1.11.%d' % idx, 'i', '4'], check=False)
    assert len(errors) == 0










# https://www.rfc-editor.org/rfc/rfc1905#section-4.2.5 (10)
def test_inconsistentValue(set_cmd):
    # Pass entry to valid
    output = subprocess.run(set_cmd + ['1.3.6.1.2.1.16.7.1.1.1.11.60000', 'i', '1'], capture_output=True, check=False)
    assert output.stderr.decode() == '''Error in packet.
Reason: inconsistentValue (The set value is illegal or unsupported in some way)
Failed object: iso.3.6.1.2.1.16.7.1.1.1.11.60000\n\n'''

# https://www.rfc-editor.org/rfc/rfc1905#section-4.2.5 (10)
def test_inconsistentValue2(set_cmd):
    # Pass entry to valid
    output = subprocess.run(set_cmd + ['1.3.6.1.2.1.16.7.1.1.1.11.60000', 'i', '3'], capture_output=True, check=False)
    assert output.stderr.decode() == '''Error in packet.
Reason: inconsistentValue (The set value is illegal or unsupported in some way)
Failed object: iso.3.6.1.2.1.16.7.1.1.1.11.60000\n\n'''

