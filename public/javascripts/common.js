$(document).ready(function() {
    //
    // initialize selectBox components
    // http://labs.abeautifulsite.net/jquery-selectBox/
    $("select").selectBox(); 

    // Create key form submit handler
    $('#create-key-form').submit(function(event) {
        event.preventDefault();
        $.post('/keys', $(this).serializeArray(), function(result, text) {
            msg({
                title: 'Success',
                contents: 'Key created: ' + result.key
            });
        })
        .error(function(err, text) {
            msg({
                title: 'Error',
                contents: 'Error creating key: ' + err.status + ' - ' + err.responseText
            });
        });
    });

    // Edit key form submit handler
    $('#edit-key-form').submit(function(event) {
        event.preventDefault();
        var key = $('input[name=apiKey]').val();
        $.ajax({
            'url': '/keys/' + key, 
            'type': 'PUT',
            'data': $(this).serializeArray(), 
            'success': function(result, text) {
                msg({
                    title: 'Success',
                    contents: 'Key updated'
                })
            }
        })
        .error(function(err, text) {
            msg({
                title: 'Error',
                contents: 'Error creating key: ' + err.status + ' - ' + err.responseText
            });
        });
    });


});

function msg(o) {
    var $dialog = $('<div></div>').html(o.contents)
        .dialog({ 
            autoOpen: true, 
            title: o.title,
            buttons: {
                "Ok" : function() {
                    $(this).dialog("close");    
                }
            }
        });
}
