/**
 * Created by Marvin Jaworski on 25.08.2015.
 */

//Create Dialogs
$('.userDialog').dialog({
    autoOpen: false,
    height: 260,
    width: 420,
    modal: true
});

$('.domainDialog').dialog({
    autoOpen: false,
    height: 260,
    width: 420,
    modal: true
});


//Click Add User Button
$('.addUser').click(function() {
    $('.userDialog').dialog( "open" );
});

//Click Add Domain Button
$('.addDomain').click(function() {
    $('.domainDialog').dialog( "open" );
});

//Click cancel Button
$('#user').click(function(el) {
    $('.userDialog').dialog( "close" );
});
$('#domain').click(function(el) {
    $('.domainDialog').dialog( "close" );
});