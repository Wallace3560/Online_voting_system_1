/*
 * Overview: Registration
 * Purpose: Handles client-side interactions for this feature.
 */
const countySelect = document.getElementById('county_id');
const constituencySelect = document.getElementById('constituency_id');
const wardSelect = document.getElementById('ward_id');
const dobInput = document.getElementById('dob');

if (dobInput) {
    const today = new Date();
    const eighteenYearsAgo = new Date(today.getFullYear() - 18, today.getMonth(), today.getDate());
    const yyyy = eighteenYearsAgo.getFullYear();
    const mm = String(eighteenYearsAgo.getMonth() + 1).padStart(2, '0');
    const dd = String(eighteenYearsAgo.getDate()).padStart(2, '0');
    const maxDob = yyyy + '-' + mm + '-' + dd;

    // Keep a broad historical range and enforce minimum age of 18 years.
    dobInput.min = '1900-01-01';
    dobInput.max = maxDob;

    // Help date pickers open around earlier years if no date has been chosen yet.
    if (!dobInput.value) {
        const defaultYear = eighteenYearsAgo.getFullYear() - 12;
        dobInput.value = defaultYear + '-01-01';
    }

    const validateAdultDob = () => {
        if (!dobInput.value) {
            dobInput.setCustomValidity('Date of birth is required.');
            return;
        }

        if (dobInput.value > maxDob) {
            dobInput.setCustomValidity('You must be at least 18 years old to register.');
            return;
        }

        dobInput.setCustomValidity('');
    };

    dobInput.addEventListener('change', validateAdultDob);
    dobInput.addEventListener('input', validateAdultDob);
    validateAdultDob();
}

if (countySelect && constituencySelect && wardSelect) {
    countySelect.addEventListener('change', function () {
        const countyId = this.value;
        constituencySelect.innerHTML = '<option value="">Loading constituencies...</option>';
        wardSelect.innerHTML = '<option value="">Select Constituency First</option>';

        if (!countyId) {
            constituencySelect.innerHTML = '<option value="">Select County First</option>';
            return;
        }

        fetch('api/get_constituencies.php?county_id=' + encodeURIComponent(countyId))
            .then((response) => response.json())
            .then((data) => {
                constituencySelect.innerHTML = '<option value="">Select Constituency</option>';
                if (!Array.isArray(data) || data.length === 0) {
                    constituencySelect.innerHTML = '<option value="">No constituencies found</option>';
                    return;
                }

                data.forEach((constituency) => {
                    const option = document.createElement('option');
                    option.value = constituency.constituency_id;
                    option.textContent = constituency.constituency_name;
                    constituencySelect.appendChild(option);
                });
            })
            .catch(() => {
                constituencySelect.innerHTML = '<option value="">Unable to load constituencies</option>';
            });
    });

    constituencySelect.addEventListener('change', function () {
        const constituencyId = this.value;
        wardSelect.innerHTML = '<option value="">Select Constituency First</option>';

        if (!constituencyId) {
            return;
        }

        wardSelect.innerHTML = '<option value="">Loading wards...</option>';

        fetch('api/get_wards.php?constituency_id=' + encodeURIComponent(constituencyId))
            .then((response) => response.json())
            .then((data) => {
                wardSelect.innerHTML = '<option value="">Select Ward</option>';
                if (!Array.isArray(data) || data.length === 0) {
                    wardSelect.innerHTML = '<option value="">No wards found</option>';
                    return;
                }

                data.forEach((ward) => {
                    const option = document.createElement('option');
                    option.value = ward.ward_id;
                    option.textContent = ward.ward_name;
                    wardSelect.appendChild(option);
                });
            })
            .catch(() => {
                wardSelect.innerHTML = '<option value="">Unable to load wards</option>';
            });
    });
}

document.querySelectorAll('.toggle-password').forEach((button) => {
    button.addEventListener('click', function () {
        const targetId = this.getAttribute('data-target');
        const input = targetId ? document.getElementById(targetId) : null;
        if (!input) {
            return;
        }

        const isPassword = input.type === 'password';
        input.type = isPassword ? 'text' : 'password';
        this.textContent = isPassword ? 'Hide' : 'Show';
        this.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
    });
});