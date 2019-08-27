function escapeId(id) {
    return id.replace('.', '\\\\.');
}

function clearHighlights() {
    $('.btn-outline-primary').each(function(i, el) {
        $(el).removeClass('btn-outline-primary');
        $(el).addClass('btn-outline-secondary'); 
    });
}

var isLoading = false;

$(document).ready(function() {
    $('#users button').click(function() {
        clearHighlights();
        isLoading = true;
        let descriptor = $(this).attr('descriptor');
        let highlight = [];
        highlight.push([descriptor, 'direct']);

        $.getJSON('/api/connections/' + descriptor, function(result) {
            isLoading = false;

            groups = result[1];
            $(groups).each(function(i, el) {
                highlight.push([el[0].descriptor, el[2]]); 
            });

            $(highlight).each(function(i, el) {
                let identifier = el[0].split('.')[1];
                let entity = $('#' + identifier);
                entity.removeClass('btn-outline-secondary');
                entity.addClass('btn-outline-primary');
            });
        });
    });
});