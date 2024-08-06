// document.addEventListener("DOMContentLoaded", function() {
//     document.getElementById('fileLink').addEventListener('click', function() {
//         showInput('fileInput');
//     });

//     document.getElementById('urlLink').addEventListener('click', function() {
//         showInput('urlInput');
//     });

//     document.getElementById('searchLink').addEventListener('click', function() {
//         showInput('searchInput');
//     });
// });

// function showInput(inputId) {
//     console.log('showInput function called with inputId:', inputId);
//     var inputs = document.querySelectorAll('.input-option');
//     for (var i = 0; i < inputs.length; i++) {
//         inputs[i].classList.add('hidden');
//     }
//     document.getElementById(inputId).classList.remove('hidden');
// }






//=====================================note ========



document.addEventListener("DOMContentLoaded", function() {
    // Set the initial active link
    var activeLink = document.querySelector('.input-link.active');
    var activeInputId = activeLink.id.replace("Link", "Input");
    showInput(activeInputId);

    // Add event listeners to all input links
    var inputLinks = document.querySelectorAll('.input-link');
    inputLinks.forEach(function(link) {
        link.addEventListener('click', function() {
            // Remove active class from previously active link
            activeLink.classList.remove('active');
            // Add active class to the clicked link
            link.classList.add('active');
            activeLink = link;

            // Show the corresponding input
            var inputId = link.id.replace("Link", "Input");
            showInput(inputId);
        });
    });
});

function showInput(inputId) {
    console.log('showInput function called with inputId:', inputId);
    var inputs = document.querySelectorAll('.input-option');
    for (var i = 0; i < inputs.length; i++) {
        inputs[i].classList.add('hidden');
    }
    document.getElementById(inputId).classList.remove('hidden');
}


function updateFileName(input) {
    var fileName = input.files[0].name;
    var fileNameSpan = document.getElementById("fileName");
    fileNameSpan.textContent = fileName;
    fileNameSpan.style.display = "inline-block";
}