document.addEventListener('DOMContentLoaded', function () {
    initializeTooltips();

    document.getElementById("searchInput")?.addEventListener('input', searchProjects)

    document.querySelectorAll('[data-dismiss="modal"]').forEach(button => {
        button.addEventListener('click', closeModal);
    });

    document.getElementById('loginDropdown')?.addEventListener('click', function (event) {
        event.stopPropagation();
        focusFirstInputField('loginDropdown');
    });
});



function searchProjects() {
    const input = document.getElementById("searchInput").value.toUpperCase();
    const projectCards = document.querySelectorAll("#projectsHolder .card");

    projectCards.forEach(card => {
        const cardTitle = card.querySelector(".card-title").innerText || card.querySelector(".card-title").textContent;
        if (cardTitle.toUpperCase().includes(input)) {
            card.style.display = "";
        } else {
            card.style.display = "none";
        }
    });
}

function closeModal(event) {
    event.stopPropagation();
    const modalElement = event.target.closest('.modal');
    if (modalElement) {
        const modalInstance = bootstrap.Modal.getOrCreateInstance(modalElement);
        modalInstance.hide();
    }
}

function initializeTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    const tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}


/**
 * Focuses the first input field within the specified element.
 * @param {string} elementId - The ID of the element containing the input field.
 */
function focusFirstInputField(elementId) {
    const dropdown = document.getElementById(elementId);
    if (dropdown) {
        const emailInput = document.querySelector('input[name="email"]');
        if (emailInput) {
            emailInput.focus();
        }
    }
}


