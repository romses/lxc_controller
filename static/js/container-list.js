var obj = null;

$('#system').change(function() {
    setVersions();
});
$('#version').change(function() {
    setArchitecture();
});

function setSystems() {
    $('#system').html('');

    $.each(obj, function( key, value ) {
        $('#system').append(new Option(key, key));
    });

    setVersions();
}

function setVersions() {
    $('#version').html('');

    var system = $('#system').val();
    $.each(obj[system], function( key, value ) {
        $('#version').append(new Option(key, key));
    });

    setArchitecture();
}

function setArchitecture() {
    $('#architecture').html('');

    var system = $('#system').val();
    var version = $('#version').val();
    $.each(obj[system][version], function( key, value ) {
        $('#architecture').append(new Option(value, value));
    });
}

$('#type').change(function() {
    var val = $('#type').val();
    if(val == 'download') {
        $('#system').css("display", "block");
        $('#version').css("display", "block");
        $('#architecture').css("display", "block");
        setSystems();
    }else{
        $('#system').css("display", "none");
        $('#version').css("display", "none");
        $('#architecture').css("display", "none");
    }
});

function clearContainer() {
    $('#name').val('');
    $('#type').val('clon');
    $('#system').css("display", "none");
    $('#version').css("display", "none");
    $('#architecture').css("display", "none");
    //Liest json datei
    $.getJSON('/lxc/images', function(data){
        obj = data;
    }, setSystems);

}
