/*
 * Overview: Admin Verify Voters
 * Purpose: Handles client-side interactions for this feature.
 */
const positionSelect = document.getElementById('position_id');
const countyWrap = document.getElementById('candidate-county-wrap');
const constituencyWrap = document.getElementById('candidate-constituency-wrap');
const wardWrap = document.getElementById('candidate-ward-wrap');
const countySelect = document.getElementById('candidate_county_id');
const constituencySelect = document.getElementById('candidate_constituency_id');
const wardSelect = document.getElementById('candidate_ward_id');

function toggleScopeFields() {
    if (!positionSelect) {
        return;
    }

    const selected = positionSelect.options[positionSelect.selectedIndex];
    const scope = selected ? selected.getAttribute('data-scope') : '';

    countyWrap.style.display = (scope === 'county') ? 'block' : 'none';
    constituencyWrap.style.display = (scope === 'constituency') ? 'block' : 'none';
    wardWrap.style.display = (scope === 'ward') ? 'block' : 'none';
}

if (positionSelect) {
    positionSelect.addEventListener('change', toggleScopeFields);
    toggleScopeFields();
}

if (countySelect && constituencySelect && wardSelect) {
    countySelect.addEventListener('change', function () {
        const countyId = this.value;
        constituencySelect.innerHTML = '<option value="">Select County First</option>';
        wardSelect.innerHTML = '<option value="">Select Constituency First</option>';

        if (!countyId) {
            return;
        }

        fetch('api/get_constituencies.php?county_id=' + encodeURIComponent(countyId))
            .then((response) => response.json())
            .then((data) => {
                constituencySelect.innerHTML = '<option value="">Select Constituency</option>';
                data.forEach((constituency) => {
                    constituencySelect.innerHTML +=
                        '<option value="' + constituency.constituency_id + '">' + constituency.constituency_name + '</option>';
                });
            })
            .catch(() => {
                constituencySelect.innerHTML = '<option value="">Unable to load constituencies</option>';
            });
    });
}

if (constituencySelect && wardSelect) {
    constituencySelect.addEventListener('change', function () {
        const constituencyId = this.value;
        wardSelect.innerHTML = '<option value="">Select Constituency First</option>';

        if (!constituencyId) {
            return;
        }

        fetch('api/get_wards.php?constituency_id=' + encodeURIComponent(constituencyId))
            .then((response) => response.json())
            .then((data) => {
                wardSelect.innerHTML = '<option value="">Select Ward</option>';
                data.forEach((ward) => {
                    wardSelect.innerHTML += '<option value="' + ward.ward_id + '">' + ward.ward_name + '</option>';
                });
            })
            .catch(() => {
                wardSelect.innerHTML = '<option value="">Unable to load wards</option>';
            });
    });
}

const candidatePositionSelects = document.querySelectorAll('.candidate-position-select');

function toggleCandidateEditScopeFields(selectEl) {
    if (!selectEl) {
        return;
    }

    const container = selectEl.closest('tr') || selectEl.closest('form');
    if (!container) {
        return;
    }

    const selected = selectEl.options[selectEl.selectedIndex];
    const scope = selected ? selected.getAttribute('data-scope') : '';

    const countyField = container.querySelector('select[name="county_id"]');
    const constituencyField = container.querySelector('select[name="constituency_id"]');
    const wardField = container.querySelector('select[name="ward_id"]');

    if (countyField) {
        countyField.disabled = scope !== 'county';
        if (countyField.disabled) {
            countyField.value = '';
        }
    }

    if (constituencyField) {
        constituencyField.disabled = scope !== 'constituency';
        if (constituencyField.disabled) {
            constituencyField.value = '';
        }
    }

    if (wardField) {
        wardField.disabled = scope !== 'ward';
        if (wardField.disabled) {
            wardField.value = '';
        }
    }
}

function loadCandidateConstituencies(countyField, constituencyField, wardField, selectedConstituencyId) {
    const countyId = countyField ? countyField.value : '';

    if (!constituencyField || !wardField) {
        return;
    }

    constituencyField.innerHTML = '<option value="">Constituency</option>';
    wardField.innerHTML = '<option value="">Ward</option>';

    if (!countyId) {
        return;
    }

    fetch('api/get_constituencies.php?county_id=' + encodeURIComponent(countyId))
        .then((response) => response.json())
        .then((data) => {
            if (!Array.isArray(data)) {
                return;
            }
            data.forEach((constituency) => {
                const option = document.createElement('option');
                option.value = constituency.constituency_id;
                option.textContent = constituency.constituency_name;
                if (selectedConstituencyId && String(selectedConstituencyId) === String(constituency.constituency_id)) {
                    option.selected = true;
                }
                constituencyField.appendChild(option);
            });
        })
        .catch(() => {
            constituencyField.innerHTML = '<option value="">Unable to load constituencies</option>';
        });
}

function loadCandidateWards(constituencyField, wardField, selectedWardId) {
    const constituencyId = constituencyField ? constituencyField.value : '';

    if (!wardField) {
        return;
    }

    wardField.innerHTML = '<option value="">Ward</option>';

    if (!constituencyId) {
        return;
    }

    fetch('api/get_wards.php?constituency_id=' + encodeURIComponent(constituencyId))
        .then((response) => response.json())
        .then((data) => {
            if (!Array.isArray(data)) {
                return;
            }
            data.forEach((ward) => {
                const option = document.createElement('option');
                option.value = ward.ward_id;
                option.textContent = ward.ward_name;
                if (selectedWardId && String(selectedWardId) === String(ward.ward_id)) {
                    option.selected = true;
                }
                wardField.appendChild(option);
            });
        })
        .catch(() => {
            wardField.innerHTML = '<option value="">Unable to load wards</option>';
        });
}

function bindCandidateLocationRow(row) {
    const countyField = row.querySelector('select[name="county_id"]');
    const constituencyField = row.querySelector('select[name="constituency_id"]');
    const wardField = row.querySelector('select[name="ward_id"]');

    if (!countyField || !constituencyField || !wardField) {
        return;
    }

    countyField.addEventListener('change', function () {
        loadCandidateConstituencies(countyField, constituencyField, wardField, null);
    });

    constituencyField.addEventListener('change', function () {
        loadCandidateWards(constituencyField, wardField, null);
    });
}

candidatePositionSelects.forEach((selectEl) => {
    selectEl.addEventListener('change', function () {
        toggleCandidateEditScopeFields(this);
    });
    toggleCandidateEditScopeFields(selectEl);

    const container = selectEl.closest('tr') || selectEl.closest('form');
    if (container) {
        bindCandidateLocationRow(container);
    }
});

document.addEventListener('change', function (event) {
    const target = event.target;
    if (!(target instanceof HTMLSelectElement)) {
        return;
    }

    if (target.classList.contains('candidate-position-select')) {
        toggleCandidateEditScopeFields(target);
        return;
    }

    const candidateForm = target.closest('form.candidate-edit-form');
    if (!candidateForm) {
        return;
    }

    const countyField = candidateForm.querySelector('select[name="county_id"]');
    const constituencyField = candidateForm.querySelector('select[name="constituency_id"]');
    const wardField = candidateForm.querySelector('select[name="ward_id"]');

    if (target.name === 'county_id' && countyField && constituencyField && wardField) {
        loadCandidateConstituencies(countyField, constituencyField, wardField, null);
        return;
    }

    if (target.name === 'constituency_id' && constituencyField && wardField) {
        loadCandidateWards(constituencyField, wardField, null);
    }
});

const byPositionSelect = document.getElementById('by_position_id');
const byCountyWrap = document.getElementById('by-county-wrap');
const byConstituencyWrap = document.getElementById('by-constituency-wrap');
const byWardWrap = document.getElementById('by-ward-wrap');

function toggleByElectionScopeFields() {
    if (!byPositionSelect) {
        return;
    }

    const selected = byPositionSelect.options[byPositionSelect.selectedIndex];
    const scope = selected ? selected.getAttribute('data-scope') : '';

    if (byCountyWrap) {
        byCountyWrap.style.display = (scope === 'county') ? 'block' : 'none';
    }
    if (byConstituencyWrap) {
        byConstituencyWrap.style.display = (scope === 'constituency') ? 'block' : 'none';
    }
    if (byWardWrap) {
        byWardWrap.style.display = (scope === 'ward') ? 'block' : 'none';
    }
}

if (byPositionSelect) {
    byPositionSelect.addEventListener('change', toggleByElectionScopeFields);
    toggleByElectionScopeFields();
}