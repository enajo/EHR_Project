// Core JavaScript Logic

// Helper function to display alerts
function showAlert(message, type = "success") {
    const alertBox = document.createElement("div");
    alertBox.className = `alert alert-${type} text-center`;
    alertBox.innerText = message;

    // Add the alert box to the top of the body
    document.body.prepend(alertBox);

    // Automatically remove the alert after 3 seconds
    setTimeout(() => {
        alertBox.remove();
    }, 3000);
}

// Handle form submissions
document.addEventListener("DOMContentLoaded", function () {
    const forms = document.querySelectorAll("form");
    forms.forEach((form) => {
        form.addEventListener("submit", (event) => {
            // Example: Validate required fields
            const requiredFields = form.querySelectorAll("[required]");
            let isValid = true;

            requiredFields.forEach((field) => {
                if (!field.value.trim()) {
                    isValid = false;
                    field.classList.add("is-invalid");
                } else {
                    field.classList.remove("is-invalid");
                }
            });

            if (!isValid) {
                event.preventDefault();
                showAlert("Please fill in all required fields.", "danger");
            }
        });
    });
});

// Navbar active link highlighting
document.addEventListener("DOMContentLoaded", () => {
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll(".nav-link");

    navLinks.forEach((link) => {
        if (link.getAttribute("href") === currentPath) {
            link.classList.add("active");
        }
    });
});

// Modal confirmation for deletions
document.addEventListener("DOMContentLoaded", () => {
    const deleteButtons = document.querySelectorAll(".btn-delete");

    deleteButtons.forEach((button) => {
        button.addEventListener("click", (event) => {
            const confirmed = confirm("Are you sure you want to delete this record?");
            if (!confirmed) {
                event.preventDefault();
            }
        });
    });
});

// Toast notifications for specific messages (Optional Enhancement)
function showToast(message, type = "success") {
    const toastContainer = document.createElement("div");
    toastContainer.className = `toast align-items-center text-bg-${type}`;
    toastContainer.role = "alert";

    const toastBody = document.createElement("div");
    toastBody.className = "toast-body";
    toastBody.innerText = message;

    toastContainer.appendChild(toastBody);
    document.body.appendChild(toastContainer);

    const toast = new bootstrap.Toast(toastContainer);
    toast.show();

    // Automatically remove the toast after display
    setTimeout(() => {
        toastContainer.remove();
    }, 5000);
}
