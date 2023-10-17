function exportTableToCSV() {
    var table = document.getElementById("data-table");
    var csv = [];
    var rows = table.getElementsByTagName("tr");
    for (var i = 0; i < rows.length; i++) {
        var row = [], cols = rows[i].querySelectorAll("td, th");
        for (var j = 0; j < cols.length; j++) {
            // Escape quotes and enclose in double quotes
            var cellContent = cols[j].innerText.replace(/"/g, '""');
            if (cellContent.includes(',') || cellContent.includes('\n')) {
                row.push('"' + cellContent + '"');
            } else {
                row.push(cellContent);
            }
        }
        csv.push(row.join(","));
    }
    downloadCSV(csv.join("\n"), 'table_data.csv');
}

function downloadCSV(csv, filename) {
    var csvFile;
    var downloadLink;

    csvFile = new Blob([csv], {type: "text/csv"});
    downloadLink = document.createElement("a");
    downloadLink.download = filename;
    downloadLink.href = window.URL.createObjectURL(csvFile);
    downloadLink.style.display = "none";
    document.body.appendChild(downloadLink);
    downloadLink.click();
}


function generatePDF() {
        var element = document.documentElement;

        html2pdf(element);
    }
