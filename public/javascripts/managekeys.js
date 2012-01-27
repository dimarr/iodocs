
$(document).ready(function() {
    // retrieve APIs and associated keys
    $.get('/apis?_cachebuster='+(new Date()).getTime(), function(apis) {
        var apiListElem = $('#apis');
        if (!apis || apis.length == 0) 
            return apiListElem.append('No APIs found');

        // display API list and key count
        $.each(apis, function(api, props) {
            var keys_csv = '';
            var count = 'N/A';
            if (props.keys && props.keys.length) {
                keys_csv = props.keys.join(',');
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
                    $.get('/apis/' + api + '/keys?_cachebuster='+(new Date()).getTime(), function(keys) {
                        var html = '<table class=api-key-table>'
                            + '<tr>'
                            + '<th width=180></th>'
                            + '<th width=250>Key</th>'
                            + '<th width=200>Application</th>'
                            + '<th width=200>Description</th>'
                            + '<th width=180>Calls / min<br><font size=1>(5m, 15m, 60m)</font></th>'
                            + '<th></th>'
                            + '</tr>';

                        $.each(keys, function(key, obj) {
                            html += '<tr>'
                                + '<td align=center>'
                                + '    <a href=/keys/' + key + '/edit>properties</a> |'
                                + '    <a href=/viewLink?link=' + api + ':' + key + '>limits</a>'
                                + '</td>'
                                + '<td align=center>' + key + '</td>'
                                + '<td>' + obj.appName + '</td>'
                                + '<td>' + obj.description + '</td>'
                                + '<td align=center>' + obj.load + '</td>'
                                + '</tr>';
                        });

                        html += '</table>';

                        $(apiElem).after(html);
                    })
                    .error (function(err, text) {
                        msg({
                            title: 'Error',
                            contents: 'Error retrieving API keys: ' + err.status + ' - ' + err.responseText
                        });
                    });
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
