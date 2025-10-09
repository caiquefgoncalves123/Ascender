function excluir(event) {
  event.preventDefault(); // impede a função padrão do elemento (no caso um link que iria recarregar a página)

  if (confirm("Tem certeza que deseja excluir esta inscrição?")) {
    document.getElementById("caixaa").style.display = "none";
    // QUANDO O USUÁRIO CLICAR EM "OK", A CAIXA SUMIRÁ (DISPLAY:NONE)
    alert("Inscrição excluída com sucesso!");
  } else {
    alert("Exclusão cancelada.");
  }
}

function esgotouAula(event) {

  event.preventDefault()

  document.getElementById("meuModal").style.display = "flex";
  // A CAIXA APARECERÁ (DISPLAY:FLEX)
}

function fecharModal() {
  document.getElementById("meuModal").style.display = "none";
  // A CAIXA SUMIRÁ (DISPLAY:NONE)
}







