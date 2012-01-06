
$(document).ready(function() {
    // retrieve APIs and associated keys
    $.get('/apis', function(apis) {
        var apiListElem = $('#apis');
        if (!apis || apis.length == 0) 
            return apiListElem.append('No APIs found');

        // display API list and key count
        $.each(apis, function(api, props) {
            var count = 'N/A';
            if (props.keys) {
                count = props.keys.length + ' key';
                if (props.keys.length > 1)
                    count += 's';
            }
            var apiElem = $('<h5>' + props.name + ' <span class="api-count">(' + count + ')</span></h5>')
                .mouseover(function() { 
                    $(this).css('cursor', 'pointer');
                })
                .click(function() {
                    if ($(this).hasClass('expanded')) 
                        return;
                    $(this).addClass('expanded');
                    if (!props.keys || !props.keys.length) {
                        $(this).after('No keys found<br>');
                    } else {
                        for (var i = 0; i < props.keys.length; i++) {
                            $(this).after(props.keys[i] + '<br>');
                        }
                    }
                });
            apiListElem.append(apiElem);
        });
    })
    .error(function(err, text) {
        msg({
            title: 'Error',
            contents: 'Error retrieving API list: ' + err.status + ' - ' + err.responseText
        });
    });
});
