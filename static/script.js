function excluir(event) {
    event.preventDefault(); // impede a função padrão do elemento (no caso um link que iria recarregar a página)

    if (confirm("Tem certeza que deseja excluir esta inscrição?")) {
        document.getElementById("caixaa").style.display = "none";
        alert("Inscrição excluída com sucesso!");
    } else {
        alert("Exclusão cancelada.");
    }
}

function esgotouAula(event) {

    event.preventDefault()

      document.getElementById("meuModal").style.display = "flex";
    }

    function fecharModal() {
      document.getElementById("meuModal").style.display = "none";
    }