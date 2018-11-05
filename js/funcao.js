function validarDataNascimento() {
    var dataNascimento = document.getElementById("txtDataNascimento").value;
    var padraoDataNascimento = /^\d{2}\/\d{2}\/\d{2,4}$/;
    if ((padraoDataNascimento.test(dataNascimento)) == false)
        return alert("O formato da Data de Nascimento não é válido, digite novamente!");
}

function validarCpf() {
    var cpf = document.getElementById("txtCpf").value;
    var padraoCpf = /^\d{3}\.\d{3}\.\d{3}\-\d{2}$/;
    if ((padraoCpf.test(cpf)) == false)
        return alert("O formato do CPF não é válido, digite novamente!");
}

function validarMatricula() {
    var matricula = document.getElementById("txtMatricula").value;
    var padraoMatricula = /^IFTM\-\d{3}\/\d{3}\-\w{2}$/i;
    if ((padraoMatricula.test(matricula)) == false)
        return alert("O formato da Matricula não é válido, digite novamente!");
}

function validarDisciplina() {
    var disciplina = document.getElementById("txtDisciplina").value;
    var padraoDisciplina = /^MT\-\d{2}\.\d{3}\-IFTM$/i;
    if ((padraoDisciplina.test(disciplina)) == false)
        return alert("O formato do Código da Disciplina do IFTM não é válido, digite novamente!");
}

function validarDisciplina2() {
    var disciplina2 = document.getElementById("txtDisciplina2").value;
    var padraoDisciplina2 = /^MT-\d{2}\.\d{3}\-(I|i)(F|f)(T|t)(M|m)$/;
    if ((padraoDisciplina2.test(disciplina2)) == false)
        return alert("O formato do Código da Disciplina do IFTM (Versão 2) não é válido, digite novamente!");
}

function validarDisciplina3() {
    var disciplina3 = document.getElementById("txtDisciplina3").value;
    var padraoDisciplina3 = /^M\s?T-\d{2}\.\d{3}\-(I|i)\s?(F|f)\s?(T|t)\s?(M|m)$/i;
    if ((padraoDisciplina3.test(disciplina3)) == false)
        return alert("O formato do Código da Disciplina do IFTM (Versão 3) não é válido, digite novamente!");
}

function validarDisciplina4() {
    var disciplina4 = document.getElementById("txtDisciplina4").value;
    var padraoDisciplina4 = /^(M|m)\s?(T|t)-\d{2}\.\d{3}\-(I|i)\s?(F|f)\s?(T|t)\s?(M|m)\s(Uberlândia Centro|Uberlândia)$/;
    if ((padraoDisciplina4.test(disciplina4)) == false)
        return alert("O formato do Código da Disciplina do IFTM (Versão 4) não é válido, digite novamente!");
}

function validarTelefone() {
    var telefone = document.getElementById("txtTelefone").value;
    var padraoTelefone = /^\+?\d?\d?\(\d{2}\)\d{5}\-\d{4}$/;
    if ((padraoTelefone.test(telefone)) == false)
        return alert("O formato do Telefone não é válido, digite novamente!");
}

function validarTelefone2() {
    var telefone2 = document.getElementById("txtTelefone2").value;
    var padraoTelefone2 = /^\(\d{2,3}\)\d{5}\-\d{4}$/;
    if ((padraoTelefone2.test(telefone2)) == false)
        return alert("O formato do Telefone (Versão 2) não é válido, digite novamente!");
}

function validarFaturamentoAnual() {
    var faturamentoAnual = document.getElementById("txtFaturamentoAnual").value;
    var padraoFaturamentoAnual = /^R\$\d?\d?\d?\.?\d?\d?\d?\.?\d?\d?\d?\.?\d?\d?\d\,\d\d?$/;
    if ((padraoFaturamentoAnual.test(faturamentoAnual)) == false)
        return alert("O formato do Faturamento Anual não é válido, digite novamente!");
}

function validarCronometro() {
    var cronometro = document.getElementById("txtCronometro").value;
    var padraoCronometro = /^([01]\d|[2][1-3])\:[0-5]\d\:[0-5]\d\:\d\d$/;
    if ((padraoCronometro.test(cronometro)) == false)
        return alert("O formato do Cronometro não é válido, digite novamente!");
}

function validarSenha() {
    var senha = document.getElementById("txtSenha").value;
    var padraoSenha = /^[A-z0-9.-_]{5,}\&[A-Pa-p]{1,}\.[aeiou]{1,}\.[A-z0-5]{1,}?\-[^0-9]{1,}\,..\.[^ab01]{1,}$/;
    if ((padraoSenha.test(senha)) == false)
        return alert("O formato da Senha não é válido, digite novamente!");
}